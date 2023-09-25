use crate::Key;
use crypter::Crypter;
use embedded_io::{
    blocking::{Read, Seek, Write},
    Io, SeekFrom,
};
use kms::KeyManagementScheme;
use persistence::PersistentStorage;
use std::marker::PhantomData;
use std::cmp::min;

pub struct BlockCryptIo<'a, IO, KMS, C, const BLK_SZ: usize, const KEY_SZ: usize, const PAD_SZ: usize> {
    io: IO,
    kms: &'a mut KMS,
    pd: PhantomData<C>,
    pos: usize
}

impl<'a, IO, KMS, C, const BLK_SZ: usize, const KEY_SZ: usize, const PAD_SZ: usize>
    BlockCryptIo<'a, IO, KMS, C, BLK_SZ, KEY_SZ, PAD_SZ>
{
    pub fn new(io: IO, kms: &'a mut KMS) -> Self {
        Self {
            io,
            kms,
            pd: PhantomData,
            pos: 0
        }
    }

    pub fn get_pad(&self) -> usize {
        PAD_SZ
    }

    // Given the size of data being stored, give number of readable bytes
    pub fn real_to_vir(&self, i: usize) -> usize {
        if i == 0 {
            return 0;
        }

        i - (PAD_SZ * ((i - 1) / BLK_SZ + 1) )
    }

}

impl<IO, KMS, C, const BLK_SZ: usize, const KEY_SZ: usize, const PAD_SZ: usize> Io
    for BlockCryptIo<'_, IO, KMS, C, BLK_SZ, KEY_SZ, PAD_SZ>
where
    IO: Io,
{
    type Error = IO::Error;
}

impl<'a, IO, KMS, C, const BLK_SZ: usize, const KEY_SZ: usize, const PAD_SZ: usize>
    BlockCryptIo<'a, IO, KMS, C, BLK_SZ, KEY_SZ, PAD_SZ>
where
    IO: Read + Seek + Write,
    KMS: KeyManagementScheme<KeyId = u64, Key = Key<KEY_SZ>>,
    C: Crypter,
{
    // Given a larger size (in readable bytes stored) it will write more bytes
    pub fn truncate(&mut self, size: usize) -> Result<usize, IO::Error> {
        let mut max_size = self.io.seek(SeekFrom::End(0))? as usize;
        println!("max size {}", max_size);
        let mut total_bytes = self.real_to_vir(max_size);
        
        // If the truncate is the same as the file size return the same size
        if total_bytes == size {
            return Ok(max_size);
        }

        // This is ok because this function doesn't change the size of the file (unless expanding)
        // Also a common case is clearing an entire file, but doing so needs doesn't need work
        if size == 0 {
            return Ok(0);
        }

        // Fill block with empty array
        let read_buf = &mut [0u8; BLK_SZ];

        let read_offset = min(size, total_bytes);

        println!("ro {}", read_offset);
        let vir_block = read_offset / (BLK_SZ - PAD_SZ);
        let block_offset = vir_block * BLK_SZ;

        // Find number of bytes needed to read
        // If the number of blocks the file truncates to is strictly less than the current number of blocks
        // Read the entire block, otherwise read the partial block
        let block_size = match size / (BLK_SZ - PAD_SZ) < total_bytes / (BLK_SZ - PAD_SZ) {
            true => BLK_SZ,
            false => max_size % (BLK_SZ),
        };
        println!("bs {}", block_size);

        // Read block
        self.io.seek(SeekFrom::Start(block_offset as u64))?;
        self.io.read_exact(&mut read_buf[0..block_size]);

        // Encrypt block
        let key = self.kms.derive(vir_block as u64).map_err(|_| ()).unwrap();
        let mut tmp_buf = match C::onetime_decrypt(&key, &read_buf[0..block_size]).map_err(|_| ()) {
            Ok(x) => x,
            Err(_) => vec![],
        };

        // Find slice needed to write
        // If the number of blocks the file trucates to is strictly greater than the current number of blocks
        // We want to write back a full block, otherwise we want to write a partial block
        let writeback_size = match total_bytes / (BLK_SZ - PAD_SZ) < size / (BLK_SZ - PAD_SZ) {
            true => BLK_SZ - PAD_SZ,
            false => size % (BLK_SZ - PAD_SZ),
        };
        tmp_buf.resize(writeback_size, 0);

        // Write back block
        self.kms.update(vir_block as u64).map_err(|_| ()).unwrap();
        let key = self.kms.derive(vir_block as u64).map_err(|_| ()).unwrap();

        tmp_buf = C::onetime_encrypt(&key, &tmp_buf).map_err(|_| ()).unwrap();
        max_size = self.io.seek(SeekFrom::Start(block_offset as u64))? as usize;
        self.io.write_all(&tmp_buf)?;
        max_size += tmp_buf.len();
        total_bytes = self.real_to_vir(max_size);
        
        // Write all the block aligned bytes, if the number of blocks is greater than the current file
        while total_bytes < size {
            let write_buf = [0u8; BLK_SZ];
            
            let byte_offset = total_bytes;
            let vir_block = total_bytes / (BLK_SZ - PAD_SZ);

            let bytes_write = match size - byte_offset > (BLK_SZ - PAD_SZ) {
                true => BLK_SZ - PAD_SZ ,
                false => size - byte_offset,
            };

            self.kms.update(vir_block as u64).map_err(|_| ()).unwrap();
            let key = self.kms.derive(vir_block.try_into().unwrap()).map_err(|_| ()).unwrap();
            let buf = C::onetime_encrypt(&key, &write_buf[0..bytes_write]).map_err(|_| ()).unwrap();

            self.io.write_all(&buf);

            total_bytes += bytes_write;

            max_size = self.io.seek(SeekFrom::End(0))? as usize;
        }

        Ok(max_size) 
    }
}

impl<IO, KMS, C, const BLK_SZ: usize, const KEY_SZ: usize, const PAD_SZ: usize> Read
    for BlockCryptIo<'_, IO, KMS, C, BLK_SZ, KEY_SZ, PAD_SZ>
where
    IO: Read + Seek,
    KMS: KeyManagementScheme<KeyId = u64, Key = Key<KEY_SZ>>,
    C: Crypter,
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let mut total = 0;
        let mut size = buf.len();

        let max_size = self.io.seek(SeekFrom::End(0))? as usize;

        let virtual_max_size = self.real_to_vir(max_size);
        let mut index = self.stream_position()? as usize;
        let read_buf = &mut [0u8; BLK_SZ];

        while size > total {
            if index >= virtual_max_size {
                return Ok(total);
            }

            let vir_block = index / (BLK_SZ - PAD_SZ);
            let real_block = vir_block * BLK_SZ;
            let to_read = match real_block + BLK_SZ < max_size {
                true => BLK_SZ,
                false => max_size - real_block
            };

            let buf_slice = &mut read_buf[0..to_read];
            self.io.seek(SeekFrom::Start(real_block.try_into().unwrap()))?;
            self.io.read_exact(buf_slice);

            let key = self.kms.derive(vir_block as u64).map_err(|_| ()).unwrap();
            let tmp_buf = C::onetime_decrypt(&key, buf_slice).map_err(|_| ()).unwrap();
            
            let left = index % (BLK_SZ - PAD_SZ);
            let right = left + min(tmp_buf.len() - left, size - total);
            buf[total.. total + right - left].copy_from_slice(&tmp_buf[left..right]);

            let width: i64 = (right - left).try_into().unwrap();
            index = self.seek(SeekFrom::Current(width))?.try_into().unwrap(); 
            total += right - left;
        }

        Ok(total)
    }
}

impl<IO, KMS, C, const BLK_SZ: usize, const KEY_SZ: usize, const PAD_SZ: usize> Write
    for BlockCryptIo<'_, IO, KMS, C, BLK_SZ, KEY_SZ, PAD_SZ>
where
    IO: Read + Write + Seek,
    KMS: KeyManagementScheme<KeyId = u64, Key = Key<KEY_SZ>>,
    C: Crypter,
{
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        let mut total = 0;
        let size = buf.len();

        let cursor = self.stream_position()? as usize;
        let mut max_size: usize = self.io.seek(SeekFrom::End(0))?.try_into().unwrap();
        let bytes_readable = self.real_to_vir(max_size);

        // If the cursor is past the size of the file, extend the file to ensure it's writable
        max_size = match cursor < bytes_readable {
            true => max_size,
            false => self.truncate(cursor)?,
        };
        
        let mut index = self.stream_position()? as usize;

        let read_buf = &mut [0u8; BLK_SZ];
        
        while total < size {
            let vir_block = index / (BLK_SZ - PAD_SZ);
            let real_block = vir_block * BLK_SZ;
            let mut tmp_buf = {
                if max_size <= real_block {
                    vec![]
                }
                else {
                    let to_read = min(max_size - real_block, BLK_SZ);
                    let buf_slice = &mut read_buf[0..to_read];
    
                    self.io.seek(SeekFrom::Start(real_block.try_into().unwrap()))?;
                    self.io.read_exact(buf_slice).unwrap();
                    let key = self.kms.derive(vir_block as u64).map_err(|_| ()).unwrap();
                    let tmp_buf = C::onetime_decrypt(&key, buf_slice).map_err(|_| ()).unwrap();

                    tmp_buf
                }
            };


            let left = index % (BLK_SZ - PAD_SZ);
            let right = left + min(size - total, BLK_SZ - PAD_SZ - left);

            if right > tmp_buf.len() {
                tmp_buf.resize(right, 0);
            }

            for i in left..right {
                tmp_buf[i] = buf[i - left];
            }
            
            self.kms.update(vir_block as u64).map_err(|_| ()).unwrap();
            let key = self.kms.derive(vir_block as u64).map_err(|_| ()).unwrap();

            tmp_buf = C::onetime_encrypt(&key, &tmp_buf).map_err(|_| ()).unwrap();
            self.io.seek(SeekFrom::Start(real_block.try_into().unwrap()))?;
            self.io.write_all(&tmp_buf)?;

            total += right - left;
            
            index = self.seek(SeekFrom::Current((right - left).try_into().unwrap()))?.try_into().unwrap();
        }

        Ok(total)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        self.io.flush()
    }
}

impl<IO, KMS, C, const BLK_SZ: usize, const KEY_SZ: usize, const PAD_SZ: usize> Seek
    for BlockCryptIo<'_, IO, KMS, C, BLK_SZ, KEY_SZ, PAD_SZ>
where
    IO: Seek,
{
    fn seek(&mut self, pos: SeekFrom) -> Result<u64, Self::Error> {
        self.pos = match pos {
            SeekFrom::Start(x) => x.try_into().unwrap(),
            SeekFrom::End(x) => {
                let end = self.io.seek(SeekFrom::End(0))? as usize;

                self.real_to_vir(end) + x as usize
            },
            SeekFrom::Current(x) => self.pos + x as usize,
        };

        Ok(self.pos.try_into().unwrap())
    }

    fn rewind(&mut self) -> Result<(), Self::Error> {
        self.pos = 0;

        Ok(())
    }

    fn stream_position(&mut self) -> Result<u64, Self::Error> {
        Ok(self.pos.try_into().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use crypter::openssl::Aes256Ctr;
    use embedded_io::{
        adapters::FromStd,
        blocking::{Read, Seek, Write},
        SeekFrom,
    };
    use hasher::openssl::{Sha3_256, SHA3_256_MD_SIZE};
    use khf::Khf;
    use rand::rngs::ThreadRng;
    use tempfile::NamedTempFile;

    const BLOCK_SIZE: usize = 4096;
    const KEY_SIZE: usize = SHA3_256_MD_SIZE;

    // Writes 4 blocks of 'a's, then 4 'b's at offset 3.
    #[test]
    fn offset_write() -> Result<()> {
        let mut khf = Khf::new(&[4, 4, 4, 4], ThreadRng::default());

        let mut blockio = BlockCryptIo::<
            FromStd<NamedTempFile>,
            Khf<ThreadRng, Sha3_256, SHA3_256_MD_SIZE>,
            Aes256Ctr,
            BLOCK_SIZE,
            KEY_SIZE,
        >::new(FromStd::new(NamedTempFile::new()?), &mut khf);

        blockio.write_all(&['a' as u8; 4 * BLOCK_SIZE])?;
        blockio.seek(SeekFrom::Start(3))?;
        blockio.write_all(&['b' as u8; 4])?;

        let mut buf = vec![0; 4 * BLOCK_SIZE];
        blockio.seek(SeekFrom::Start(0))?;
        blockio.read_exact(&mut buf)?;

        assert_eq!(&buf[..3], &['a' as u8; 3]);
        assert_eq!(&buf[3..7], &['b' as u8; 4]);
        assert_eq!(&buf[7..], &['a' as u8; 4 * BLOCK_SIZE - 7]);

        Ok(())
    }

    // Writes 2 blocks of 'a's and a block of 'b' right in the middle.
    #[test]
    fn misaligned_write() -> Result<()> {
        let mut khf = Khf::new(&[4, 4, 4, 4], ThreadRng::default());

        let mut blockio = BlockCryptIo::<
            FromStd<NamedTempFile>,
            Khf<ThreadRng, Sha3_256, SHA3_256_MD_SIZE>,
            Aes256Ctr,
            BLOCK_SIZE,
            KEY_SIZE,
        >::new(FromStd::new(NamedTempFile::new()?), &mut khf);

        blockio.write_all(&['a' as u8; 2 * BLOCK_SIZE])?;
        blockio.seek(SeekFrom::Start((BLOCK_SIZE / 2) as u64))?;
        blockio.write_all(&['b' as u8; BLOCK_SIZE])?;

        let mut buf = vec![0; 2 * BLOCK_SIZE];
        blockio.seek(SeekFrom::Start(0))?;
        blockio.read_exact(&mut buf)?;

        assert_eq!(&buf[..BLOCK_SIZE / 2], &['a' as u8; BLOCK_SIZE / 2]);
        assert_eq!(
            &buf[BLOCK_SIZE / 2..BLOCK_SIZE / 2 + BLOCK_SIZE],
            &['b' as u8; BLOCK_SIZE]
        );
        assert_eq!(
            &buf[BLOCK_SIZE / 2 + BLOCK_SIZE..],
            &['a' as u8; BLOCK_SIZE / 2]
        );

        Ok(())
    }

    #[test]
    fn short_write() -> Result<()> {
        let mut khf = Khf::new(&[4, 4, 4, 4], ThreadRng::default());

        let mut blockio = BlockCryptIo::<
            FromStd<NamedTempFile>,
            Khf<ThreadRng, Sha3_256, SHA3_256_MD_SIZE>,
            Aes256Ctr,
            BLOCK_SIZE,
            KEY_SIZE,
        >::new(FromStd::new(NamedTempFile::new()?), &mut khf);

        blockio.write_all(&['a' as u8])?;
        blockio.write_all(&['b' as u8])?;

        let mut buf = vec![0; 2];
        blockio.seek(SeekFrom::Start(0))?;
        blockio.read_exact(&mut buf)?;

        assert_eq!(&buf[..], &['a' as u8, 'b' as u8]);

        Ok(())
    }

    #[test]
    fn read_too_much() -> Result<()> {
        let mut khf = Khf::new(&[4, 4, 4, 4], ThreadRng::default());

        let mut blockio = BlockCryptIo::<
            FromStd<NamedTempFile>,
            Khf<ThreadRng, Sha3_256, SHA3_256_MD_SIZE>,
            Aes256Ctr,
            BLOCK_SIZE,
            KEY_SIZE,
        >::new(FromStd::new(NamedTempFile::new()?), &mut khf);

        blockio.write_all(&['a' as u8; 16])?;

        let mut buf = vec![0; BLOCK_SIZE];
        blockio.seek(SeekFrom::Start(0).into())?;
        let n = blockio.read(&mut buf)?;

        assert_eq!(n, 16);
        assert_eq!(&buf[..n], &['a' as u8; 16]);

        Ok(())
    }
}
