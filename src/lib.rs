pub mod error;
pub mod io;
pub mod result;

use allocator::Allocator;
use crypter::Crypter;
use embedded_io::{
    blocking::{Read, Seek, Write},
    SeekFrom,
};
use error::Error;
use hasher::Hasher;
use io::{BlockCryptIo, BlockRecryptIo, CryptIo};
use khf::{Consolidation, Khf};
use kms::KeyManagementScheme;
use persistence::{Persist, PersistentStorage};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, marker::PhantomData};

pub(crate) type Key<const N: usize> = [u8; N];

// Default `Khf` fanouts.
const DEFAULT_MASTER_KHF_FANOUTS: &[u64; 4] = &[4, 4, 4, 4];
const DEFAULT_OBJECT_KHF_FANOUTS: &[u64; 4] = &[4, 4, 4, 4];

// Reserved object IDs.
const MASTER_KHF_OBJID: u64 = 0;
const OBJECT_KHF_FANOUTS_OBJID: u64 = 1;
const ALLOCATOR_OBJID: u64 = 2;
const MAPPINGS_OBJID: u64 = 3;

pub struct Lethe<S, P, A, R, C, H, const E: usize, const D: usize>
where
    S: Read + Write + Seek,
    P: PersistentStorage<Id = u64>,
    <P as PersistentStorage>::Flags: Default,
    for<'a> <P as PersistentStorage>::Io<'a>: Read + Write + Seek,
    for<'a> A: Allocator<Id = u64> + Default + Serialize + Deserialize<'a>,
    R: RngCore + CryptoRng + Clone + Default,
    C: Crypter,
    H: Hasher<E>,
{
    master_key: Key<E>,
    master_khf: Khf<R, H, E>,
    object_khfs: HashMap<u64, Khf<R, H, E>>,
    object_khf_fanouts: Vec<u64>,
    allocator: A,
    mappings: HashMap<u64, MapEntry>,
    enclave: S,
    pub storage: P,
    pd: PhantomData<C>,
}

#[derive(Serialize, Deserialize)]
pub struct MapEntry {
    pub map_id: u64,
    pub khf_id: u64,
}

impl<S, P, A, R, C, H, const E: usize, const D: usize> Lethe<S, P, A, R, C, H, E, D>
where
    S: Read + Write + Seek,
    P: PersistentStorage<Id = u64>,
    <P as PersistentStorage>::Flags: Default,
    for<'a> <P as PersistentStorage>::Io<'a>: Read + Write + Seek,
    for<'a> A: Allocator<Id = u64> + Default + Serialize + Deserialize<'a>,
    R: RngCore + CryptoRng + Clone + Default,
    C: Crypter,
    H: Hasher<E>,
{
    /// Creates a new `Lethe` instance.
    pub fn new(enclave: S, storage: P) -> Self {
        let mut master_key = [0; E];
        R::default().fill_bytes(&mut master_key);

        let mut lethe = Self {
            master_key,
            master_khf: Khf::new(DEFAULT_MASTER_KHF_FANOUTS, R::default()),
            object_khfs: HashMap::new(),
            object_khf_fanouts: DEFAULT_MASTER_KHF_FANOUTS.to_vec(),
            allocator: A::default(),
            mappings: HashMap::new(),
            enclave,
            storage,
            pd: PhantomData,
        };

        for id in [
            MASTER_KHF_OBJID,
            OBJECT_KHF_FANOUTS_OBJID,
            ALLOCATOR_OBJID,
            MAPPINGS_OBJID,
        ] {
            lethe.allocator.reserve(id).unwrap();
            lethe
                .storage
                .create(&id, &<P as PersistentStorage>::Flags::default())
                .unwrap();
        }

        lethe
    }

    /// Creates a new `LetheBuilder` instance.
    pub fn options() -> LetheBuilder<S, P, A, R, C, H, E, D> {
        LetheBuilder::new()
    }

    /// Loads a persisted object `Khf`.
    fn load_khf(&mut self, objid: u64) -> Result<(), Error> {
        let entry = self.mappings.get(&objid).ok_or(Error::MissingKhf)?;

        // If the object `Khf` is already loaded, we're done.
        if self.object_khfs.contains_key(&entry.khf_id) {
            return Ok(());
        }

        // Construct the `Io` to load the object `Khf`.
        let key = self.master_khf.derive(entry.khf_id)?;
        let io = CryptIo::<<P as PersistentStorage>::Io<'_>, C, E>::new(
            self.storage
                .read_handle(&entry.khf_id)
                .map_err(|_| Error::Io)?,
            key,
        );

        // Only IO errors should prevent the object `Khf` from being loaded.
        let khf = Khf::load(io)?;
        self.object_khfs.insert(entry.khf_id, khf);

        Ok(())
    }

    /// Returns the mapping of an object ID.
    pub fn get_khf_mapping(&self, objid: u64) -> Option<&MapEntry> {
        self.mappings.get(&objid)
    }

    /// Returns an immutable reference to an object `Khf`.
    pub fn get_khf(&mut self, objid: u64) -> Result<Option<&Khf<R, H, E>>, Error> {
        self.load_khf(objid)?;
        Ok(self
            .mappings
            .get(&objid)
            .map(|entry| self.object_khfs.get(&entry.khf_id))
            .flatten())
    }

    /// Returns a mutable reference to an object `Khf`.
    pub fn get_khf_mut(&mut self, objid: u64) -> Result<Option<&mut Khf<R, H, E>>, Error> {
        self.load_khf(objid)?;
        Ok(self
            .mappings
            .get(&objid)
            .map(|entry| self.object_khfs.get_mut(&entry.khf_id))
            .flatten())
    }

    /// Returns an immutable reference to the master `Khf`.
    pub fn get_master_khf(&self) -> &Khf<R, H, E> {
        &self.master_khf
    }

    /// Consolidates an object `Khf` using the specified `mechanism`.
    pub fn consolidate_khf(&mut self, objid: u64, mechanism: Consolidation) -> Result<(), Error> {
        self.load_khf(objid)?;

        if let Some(entry) = self.mappings.get(&objid) {
            let mut curr_khf = self.object_khfs.get_mut(&entry.khf_id).unwrap();
            let mut next_khf = curr_khf.clone();
            let blocks = next_khf.consolidate(mechanism);

            let mut io = BlockRecryptIo::<
                <P as PersistentStorage>::Io<'_>,
                Khf<R, H, E>,
                Khf<R, H, E>,
                C,
                D,
                E,
            >::new(
                self.storage
                    .rw_handle(&entry.khf_id)
                    .map_err(|_| Error::Io)?,
                &mut curr_khf,
                &mut next_khf,
            );

            for block in blocks {
                let mut buf = [0; D];

                io.seek(SeekFrom::Start(block * D as u64))
                    .map_err(|_| Error::Io)?;
                let n = io.read(&mut buf).map_err(|_| Error::Io)?;

                io.seek(SeekFrom::Start(block * D as u64))
                    .map_err(|_| Error::Io)?;
                io.write_all(&buf[..n]).map_err(|_| Error::Io)?;
            }

            *curr_khf = next_khf;
        }

        Ok(())
    }

    /// Consolidates the master `Khf` using the specified `mechanism`.
    pub fn consolidate_master_khf(&mut self, mechanism: Consolidation) {
        self.master_khf.consolidate(mechanism);
    }
}

impl<S, P, A, R, C, H, const E: usize, const D: usize> PersistentStorage
    for Lethe<S, P, A, R, C, H, E, D>
where
    S: Read + Write + Seek,
    P: PersistentStorage<Id = u64>,
    <P as PersistentStorage>::Flags: Default,
    for<'a> <P as PersistentStorage>::Io<'a>: Read + Write + Seek,
    for<'a> A: Allocator<Id = u64> + Default + Serialize + Deserialize<'a>,
    R: RngCore + CryptoRng + Clone + Default,
    C: Crypter,
    H: Hasher<E>,
{
    type Id = u64;
    type Flags = <P as PersistentStorage>::Flags;
    type Info = <P as PersistentStorage>::Info;
    type Error = Error;
    type Io<'a> = BlockCryptIo<'a, P::Io<'a>, Khf<R, H, E>, C, D, E, 40>
        where
            S: 'a,
            P: 'a,
            A: 'a,
            R: 'a,
            H: 'a,
            C: 'a;

    fn create(&mut self, objid: &Self::Id, flags: &Self::Flags) -> Result<(), Self::Error> {
        let map_id = self.allocator.alloc().map_err(|_| Error::Alloc)?;
        let khf_id = self.allocator.alloc().map_err(|_| Error::Alloc)?;

        self.mappings.insert(*objid, MapEntry { map_id, khf_id });

        self.object_khfs
            .insert(khf_id, Khf::new(&self.object_khf_fanouts, R::default()));
        self.master_khf.update(khf_id)?;

        self.storage
            .create(&khf_id, &<P as PersistentStorage>::Flags::default())
            .map_err(|_| Error::Io)?;
        self.storage
            .create(&map_id, &flags)
            .map_err(|_| Error::Io)?;

        Ok(())
    }

    fn destroy(&mut self, objid: &Self::Id) -> Result<(), Self::Error> {
        if let Some(entry) = self.mappings.remove(objid) {
            self.allocator
                .dealloc(entry.map_id)
                .map_err(|_| Error::Dealloc)?;
            self.allocator
                .dealloc(entry.khf_id)
                .map_err(|_| Error::Dealloc)?;

            self.object_khfs.remove(&entry.khf_id);
            self.master_khf.update(entry.khf_id)?;

            self.storage.destroy(&entry.khf_id).map_err(|_| Error::Io)?;
            self.storage.destroy(&entry.map_id).map_err(|_| Error::Io)?;

            self.master_khf.commit();
        }
        Ok(())
    }

    fn get_info(&mut self, objid: &Self::Id) -> Result<Self::Info, Self::Error> {
        self.storage.get_info(objid).map_err(|_| Error::Io)
    }

    fn set_info(&mut self, objid: &Self::Id, info: Self::Info) -> Result<(), Self::Error> {
        self.storage.set_info(objid, info).map_err(|_| Error::Io)
    }

    fn read_handle(&mut self, objid: &Self::Id) -> Result<Self::Io<'_>, Self::Error> {
        self.load_khf(*objid)?;
        let entry = self.mappings.get(objid).ok_or(Error::MissingKhf)?;
        let khf = self
            .object_khfs
            .get_mut(&entry.khf_id)
            .ok_or(Error::MissingKhf)?;
        let io = self
            .storage
            .read_handle(&entry.map_id)
            .map_err(|_| Error::Io)?;
        Ok(BlockCryptIo::new(io, khf))
    }

    fn write_handle(&mut self, objid: &Self::Id) -> Result<Self::Io<'_>, Self::Error> {
        self.load_khf(*objid)?;

        let entry = self.mappings.get(objid).ok_or(Error::MissingKhf)?;
        let khf = self
            .object_khfs
            .get_mut(&entry.khf_id)
            .ok_or(Error::MissingKhf)?;
        let io = self
            .storage
            .rw_handle(&entry.map_id)
            .map_err(|_| Error::Io)?;

        self.master_khf.update(entry.khf_id)?;

        Ok(BlockCryptIo::new(io, khf))
    }

    fn rw_handle(&mut self, objid: &Self::Id) -> Result<Self::Io<'_>, Self::Error> {
        self.write_handle(objid)
    }

    fn truncate(&mut self, objid: &Self::Id, size: u64) -> Result<(), Self::Error> {
        let map_id = {
            let entry: &MapEntry = self.mappings.get(objid).ok_or(Error::MissingKhf)?;
            entry.map_id
        };

        // Cut off the tail from 
        let real_size = {
            let mut x = self.rw_handle(objid).unwrap();

            x.truncate(size.try_into().unwrap()).unwrap()
        };

        // Truncate the storage medium that 'removes' the bytes from the file
        self.storage.truncate(&map_id, real_size.try_into().unwrap()).unwrap();

        // Truncate the forest. Not needed for security, but nice for efficiency.
        {
            let keys = (size + ((D - 40) as u64 - 1)) / (D - 40) as u64;
            self.get_khf_mut(*objid)?
                .ok_or(Error::MissingKhf)?
                .truncate(keys);
        }
    


        Ok(())
    }

    fn persist_state(&mut self) -> Result<(), Self::Error> {
        // Persist the updated object `Khf`s.
        for khf_id in self.master_khf.commit() {
            let khf = self.object_khfs.get_mut(&khf_id).unwrap();
            khf.commit();

            let ser = bincode::serialize(khf)?;
            let key = self.master_khf.derive(khf_id)?;
            let mut io = CryptIo::<<P as PersistentStorage>::Io<'_>, C, E>::new(
                self.storage.write_handle(&khf_id).map_err(|_| Error::Io)?,
                key,
            );

            io.write_all(&ser).map_err(|_| Error::Io)?;
        }

        // Generate new master key.
        R::default().fill_bytes(&mut self.master_key);

        // Persist the master `Khf`.
        {
            let mut io = CryptIo::<<P as PersistentStorage>::Io<'_>, C, E>::new(
                self.storage
                    .write_handle(&MASTER_KHF_OBJID)
                    .map_err(|_| Error::Io)?,
                self.master_key,
            );
            let ser = bincode::serialize(&self.master_khf)?;

            io.write_all(&ser).map_err(|_| Error::Io)?;
        }

        // Persist the object `Khf` fanouts.
        {
            let mut io = CryptIo::<<P as PersistentStorage>::Io<'_>, C, E>::new(
                self.storage
                    .write_handle(&OBJECT_KHF_FANOUTS_OBJID)
                    .map_err(|_| Error::Io)?,
                self.master_key,
            );
            let ser = bincode::serialize(&self.object_khf_fanouts)?;
            io.write_all(&ser).map_err(|_| Error::Io)?;
        }

        // Persist the allocator.
        {
            let mut io = CryptIo::<<P as PersistentStorage>::Io<'_>, C, E>::new(
                self.storage
                    .write_handle(&ALLOCATOR_OBJID)
                    .map_err(|_| Error::Io)?,
                self.master_key,
            );
            let ser = bincode::serialize(&self.allocator)?;
            io.write_all(&ser).map_err(|_| Error::Io)?;
        }

        // Persist the mappings.
        {
            let mut io = CryptIo::<<P as PersistentStorage>::Io<'_>, C, E>::new(
                self.storage
                    .write_handle(&MAPPINGS_OBJID)
                    .map_err(|_| Error::Io)?,
                self.master_key,
            );
            let ser = bincode::serialize(&self.mappings)?;
            io.write_all(&ser).map_err(|_| Error::Io)?;
        }

        // Persist the master key.
        self.enclave
            .seek(SeekFrom::Start(0))
            .map_err(|_| Error::Io)?;
        self.enclave
            .write_all(&self.master_key)
            .map_err(|_| Error::Io)?;

        // Persist state of the underlying storage.
        self.storage.persist_state().map_err(|_| Error::Io)
    }

    fn load_state(&mut self) -> Result<(), Self::Error> {
        // Load state of the underlying storage.
        self.storage.load_state().map_err(|_| Error::Io)?;

        // Load the master key.
        let mut master_key = [0; E];
        self.enclave
            .seek(SeekFrom::Start(0))
            .map_err(|_| Error::Io)?;
        self.enclave
            .read_exact(&mut master_key)
            .map_err(|_| Error::Io)?;

        // Load the master `Khf`.
        let master_khf = {
            let mut io = CryptIo::<<P as PersistentStorage>::Io<'_>, C, E>::new(
                self.storage
                    .read_handle(&MASTER_KHF_OBJID)
                    .map_err(|_| Error::Io)?,
                master_key,
            );
            let mut ser = vec![];
            io.read_to_end(&mut ser).map_err(|_| Error::Io)?;
            bincode::deserialize(&ser)?
        };

        // Load the object `Khf` fanouts.
        let object_khf_fanouts = {
            let mut io = CryptIo::<<P as PersistentStorage>::Io<'_>, C, E>::new(
                self.storage
                    .read_handle(&OBJECT_KHF_FANOUTS_OBJID)
                    .map_err(|_| Error::Io)?,
                master_key,
            );
            let mut ser = vec![];
            io.read_to_end(&mut ser).map_err(|_| Error::Io)?;
            bincode::deserialize(&ser)?
        };

        // Load the allocator.
        let allocator = {
            let mut io = CryptIo::<<P as PersistentStorage>::Io<'_>, C, E>::new(
                self.storage
                    .read_handle(&ALLOCATOR_OBJID)
                    .map_err(|_| Error::Io)?,
                master_key,
            );
            let mut ser = vec![];
            io.read_to_end(&mut ser).map_err(|_| Error::Io)?;
            bincode::deserialize(&ser)?
        };

        // Load the mappings.
        let mappings = {
            let mut io = CryptIo::<<P as PersistentStorage>::Io<'_>, C, E>::new(
                self.storage
                    .read_handle(&MAPPINGS_OBJID)
                    .map_err(|_| Error::Io)?,
                master_key,
            );
            let mut ser = vec![];
            io.read_to_end(&mut ser).map_err(|_| Error::Io)?;
            bincode::deserialize(&ser)?
        };

        // Update state after all the fallible operations.
        self.master_key = master_key;
        self.master_khf = master_khf;
        self.object_khf_fanouts = object_khf_fanouts;
        self.allocator = allocator;
        self.mappings = mappings;

        Ok(())
    }
}

impl<S, P, A, R, C, H, const E: usize, const D: usize> Drop for Lethe<S, P, A, R, C, H, E, D>
where
    S: Read + Write + Seek,
    P: PersistentStorage<Id = u64>,
    <P as PersistentStorage>::Flags: Default,
    for<'a> <P as PersistentStorage>::Io<'a>: Read + Write + Seek,
    for<'a> A: Allocator<Id = u64> + Default + Serialize + Deserialize<'a>,
    R: RngCore + CryptoRng + Clone + Default,
    C: Crypter,
    H: Hasher<E>,
{
    fn drop(&mut self) {
        self.persist_state().unwrap();
    }
}

pub struct LetheBuilder<S, P, A, R, C, H, const E: usize, const D: usize> {
    master_khf_fanouts: Vec<u64>,
    object_khf_fanouts: Vec<u64>,
    pd: PhantomData<(S, P, A, R, C, H)>,
}

impl<S, P, A, R, C, H, const E: usize, const D: usize> LetheBuilder<S, P, A, R, C, H, E, D>
where
    S: Read + Write + Seek,
    P: PersistentStorage<Id = u64>,
    <P as PersistentStorage>::Flags: Default,
    for<'a> <P as PersistentStorage>::Io<'a>: Read + Write + Seek,
    for<'a> A: Allocator<Id = u64> + Default + Serialize + Deserialize<'a>,
    R: RngCore + CryptoRng + Clone + Default,
    C: Crypter,
    H: Hasher<E>,
{
    pub fn new() -> Self {
        Self {
            master_khf_fanouts: DEFAULT_MASTER_KHF_FANOUTS.to_vec(),
            object_khf_fanouts: DEFAULT_OBJECT_KHF_FANOUTS.to_vec(),
            pd: PhantomData,
        }
    }

    pub fn master_khf_fanouts(&mut self, fanouts: &[u64]) -> &mut Self {
        self.master_khf_fanouts = fanouts.to_vec();
        self
    }

    pub fn object_khf_fanouts(&mut self, fanouts: &[u64]) -> &mut Self {
        self.object_khf_fanouts = fanouts.to_vec();
        self
    }

    pub fn build(&mut self, enclave: S, storage: P) -> Lethe<S, P, A, R, C, H, E, D> {
        let mut master_key = [0; E];
        R::default().fill_bytes(&mut master_key);

        let mut lethe = Lethe {
            master_key,
            master_khf: Khf::new(&self.master_khf_fanouts, R::default()),
            object_khfs: HashMap::new(),
            object_khf_fanouts: self.object_khf_fanouts.clone(),
            allocator: A::default(),
            mappings: HashMap::new(),
            enclave,
            storage,
            pd: PhantomData,
        };

        for id in [
            MASTER_KHF_OBJID,
            OBJECT_KHF_FANOUTS_OBJID,
            ALLOCATOR_OBJID,
            MAPPINGS_OBJID,
        ] {
            lethe.allocator.reserve(id).unwrap();
            lethe
                .storage
                .create(&id, &<P as PersistentStorage>::Flags::default())
                .unwrap();
        }

        lethe
    }
}
