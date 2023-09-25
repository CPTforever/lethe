use crate::Key;
use crypter::Crypter;
use embedded_io::{
    blocking::{Read, Seek, Write},
    Io, SeekFrom,
};
use std::marker::PhantomData;

pub struct CryptIo<IO, C, const KEY_SZ: usize> {
    key: Key<KEY_SZ>,
    io: IO,
    pd: PhantomData<C>,
}

impl<IO, C, const KEY_SZ: usize> CryptIo<IO, C, KEY_SZ> {
    pub fn new(io: IO, key: Key<KEY_SZ>) -> Self {
        Self {
            io,
            key,
            pd: PhantomData,
        }
    }
}

impl<IO, C, const KEY_SZ: usize> Io for CryptIo<IO, C, KEY_SZ>
where
    IO: Io,
{
    type Error = IO::Error;
}

impl<IO, C, const KEY_SZ: usize> Read for CryptIo<IO, C, KEY_SZ>
where
    IO: Read,
    C: Crypter,
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, IO::Error> {
        let mut encrypted = vec![0; buf.len()];
        let n = self.io.read(&mut encrypted)?;

        let decrypted = C::onetime_decrypt(&self.key, &encrypted)
            .map_err(|_| ())
            .unwrap();
        buf.copy_from_slice(&decrypted[..]);

        Ok(n)
    }

    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> Result<usize, Self::Error> {
        self.io.read_to_end(buf)?;

        let x = C::onetime_decrypt(&self.key, &buf)
            .map_err(|_| ())
            .unwrap();
        buf.clone_from(&x);
        Ok(buf.len())
    }
}

impl<IO, C, const KEY_SZ: usize> Write for CryptIo<IO, C, KEY_SZ>
where
    IO: Write,
    C: Crypter,
{
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        let encrypted = C::onetime_encrypt(&self.key, buf).map_err(|_| ()).unwrap();
        Ok(self.io.write(&encrypted)?)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        self.io.flush()
    }

    /// Write an entire buffer into this writer.
    fn write_all(&mut self, mut buf: &[u8]) -> Result<(), Self::Error> {
        let encrypted = C::onetime_encrypt(&self.key, buf).map_err(|_| ()).unwrap();

        self.io.write_all(&encrypted)?;

        Ok(())
    }
}

impl<IO, C, const KEY_SZ: usize> Seek for CryptIo<IO, C, KEY_SZ>
where
    IO: Seek,
    C: Crypter,
{
    fn seek(&mut self, pos: SeekFrom) -> Result<u64, Self::Error> {
        self.io.seek(pos)
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
    use hasher::openssl::SHA3_256_MD_SIZE;
    use rand::{thread_rng, RngCore};
    use tempfile::NamedTempFile;

    const BLOCK_SIZE: usize = 4096;
    const KEY_SIZE: usize = SHA3_256_MD_SIZE;

    // Writes 4 blocks of 'a's, then 4 'b's at offset 3.
    #[test]
    fn it_works() -> Result<()> {
        let mut key = [0; KEY_SIZE];
        thread_rng().fill_bytes(&mut key);

        let mut cryptio = CryptIo::<FromStd<NamedTempFile>, Aes256Ctr, KEY_SIZE>::new(
            FromStd::new(NamedTempFile::new()?),
            key,
        );

        cryptio.write_all(&['a' as u8; 4 * BLOCK_SIZE])?;

        let mut buf = vec![0; 4 * BLOCK_SIZE];
        cryptio.seek(SeekFrom::Start(0))?;
        cryptio.read_exact(&mut buf)?;

        assert_eq!(&buf[..], &['a' as u8; 4 * BLOCK_SIZE]);

        Ok(())
    }
}
