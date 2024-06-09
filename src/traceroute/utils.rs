use std::collections::HashSet;
use rand::prelude::ThreadRng;
use rand::Rng;

pub mod dns;
pub mod bytes;
pub mod packet_utils;

pub struct RandomUniquePort {
    generated_ports: HashSet<u16>,
    rng: ThreadRng
}

impl RandomUniquePort {
    pub fn new() -> Self {
        Self {
            generated_ports: HashSet::with_capacity(10),
            rng: rand::thread_rng()
        }
    }

    pub fn generate_ports(&mut self, tot_ports: u16) -> HashSet<u16> {
        let mut generated_ports = HashSet::with_capacity(tot_ports as usize);

        for _ in 0..tot_ports {
            let generated_port = self.generate_port();
            generated_ports.insert(generated_port);
        }

        generated_ports
    }

    pub fn generate_port(&mut self) -> u16 {
        let mut generated_port: u16 = 0;

        let mut not_found = true;
        while not_found {
            generated_port = self.rng.gen_range(0..=65535);
            not_found = self.generated_ports.contains(&generated_port);
        }

        self.generated_ports.insert(generated_port);
        generated_port
    }
}