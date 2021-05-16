use std::collections::HashSet;
use std::time::Instant;
use std::u8;

const N_BITS: u8 = 3;

const N_LOCS: usize = 1 << N_BITS;
const LOC_MASK: usize = N_LOCS - 1;
const BIT_MASK: usize = 0xFF;

/*
/// All the possible ops
#[derive(Debug, Clone, Copy)]
#[repr(usize)]
enum Op {
    NOP,
    LDA,
    ADD,
    SUB,
    STA,
    LDI,
    JMP,
    JC,
    JZ,
    NINE,
    A,
    B,
    C,
    D,
    OUT,
    HLT,
}

/// A command is a type with an operand
//type Command = (Op, usize);

fn op_from_mem(byte: usize) -> Op {
    match byte >> 4 {
        0 => Op::NOP,
        1 => Op::LDA,
        2 => Op::ADD,
        3 => Op::SUB,
        4 => Op::STA,
        5 => Op::LDI,
        6 => Op::JMP,
        7 => Op::JC,
        8 => Op::JZ,
        9 => Op::NINE,
        10 => Op::A,
        11 => Op::B,
        12 => Op::C,
        13 => Op::D,
        14 => Op::OUT,
        15 => Op::HLT,
        _ => Op::NOP,
    }
}
*/

//fn command_to_u8(cmd: Command) -> u8 {
//    (cmd.0 as u8) << 4 + cmd.1
//}

/*
fn u8_to_command(byte: usize) -> Command {
    (op_from_mem(byte), (byte & 0x0F))
}
*/

type StateTuple = (usize, [usize; N_LOCS]);

// pc, a, carry, zero
// N_BITS + N_BITS + 1 + 1
// mem is 2^N_BITS * 8
//fn hash_state (pc, a, carry, zero, mem) -> u128 {}

#[derive(Debug)]
struct State {
    mem: [usize; N_LOCS],

    pc: usize,
    a: usize,
    carry: bool,
    zero: bool,
}

impl State {
    pub fn new_raw(u8_mem: [usize; N_LOCS]) -> State {
        State {
            pc: 0,
            a: 0,
            mem: u8_mem,
            carry: false,
            zero: true,
        }
    }

    /// Returns the next state
    pub fn iter_until_halt_or_loop(
        self: &Self,
        _seen_states: &mut HashSet<StateTuple>,
    ) -> Result<usize, usize> {
        //let mut seen_quick = HashSet::new();
        let mut seen_states = HashSet::new();

        let mut pc = self.pc;
        let mut a = self.a;
        let mut mem = self.mem;
        let mut carry = self.carry;
        let mut zero = self.zero;

        let mut count = 0;

        loop {
            let op = mem[pc] >> 4;
            let operand = mem[pc] & 0x0F;

            let mut quick_hash = (pc << 16) + (a << 8);
            if carry {
                quick_hash += 2;
            }
            if zero {
                quick_hash += 1;
            }

            //if seen_quick.contains(&quick_hash) {
            let state_tuple = (quick_hash, mem);
            if seen_states.contains(&state_tuple) {
                return Err(count);
            }
            seen_states.insert(state_tuple);
            //}
            //seen_quick.insert(quick_hash);

            count += 1;

            pc += 1;

            match op as usize {
                1 => a = mem[operand & LOC_MASK],
                2 => {
                    a += mem[operand & LOC_MASK];
                    carry = a > 255;

                    a = a & BIT_MASK;
                    zero = a == 0;
                }

                3 => {
                    a += 256 - mem[operand & LOC_MASK];
                    carry = a > 255;
                    a = a & BIT_MASK;
                    zero = a == 0;
                }
                4 => mem[operand & LOC_MASK] = a,
                5 => a = operand,
                6 => pc = operand,
                7 => {
                    if carry {
                        pc = operand
                    }
                }
                8 => {
                    if zero {
                        pc = operand
                    }
                }
                15 => break,
                _ => (),
            }

            //let a = (a % (1 << 8)) as i8;
            //let pc = pc % N_LOCS;
            pc = pc & LOC_MASK;
        }
        Ok(count)
    }
}

fn i_to_mem(mem_int: u128) -> [usize; N_LOCS] {
    let mut mem = [1; N_LOCS];
    for i in 0..N_LOCS {
        mem[(i) % N_LOCS] = ((mem_int >> (8 * i)) + 1 + (6 << 4)) as usize & BIT_MASK;
    }

    mem
}

fn main() {
    let mut tot_counts = 0;
    let mut cur_max = 0;
    let mut cur_max_mem = [0; N_LOCS];

    let mut cur_max_loop = 0;
    let mut cur_max_loop_mem = [0; N_LOCS];

    let max_mem: u128 = 1 << (N_LOCS * 8);
    //let test_mem = max_mem >> 13;
    let test_mem = max_mem;

    let start = Instant::now();
    let mut seen_states = HashSet::new();
    for mem_int in 1..test_mem {
        let m = i_to_mem(mem_int);

        let s = State::new_raw(m);
        let count = s.iter_until_halt_or_loop(&mut seen_states);

        if let Ok(c) = count {
            if c > cur_max {
                cur_max = c;
                cur_max_mem = m;
                println!();
                println!("{} with mem {:?}", cur_max, cur_max_mem);
                for v in cur_max_mem.iter() {
                    print!("{:02x}", v);
                }
                println!();
            }
            tot_counts += c;
        }

        if let Err(c) = count {
            if c > cur_max_loop {
                cur_max_loop = c;
                cur_max_loop_mem = m;

                println!();
                println!("Loop {} with mem {:?},", cur_max_loop, cur_max_loop_mem,);
                for v in cur_max_loop_mem.iter() {
                    print!("{:02x}", v);
                }
                println!();
            }
            tot_counts += c;
        }
    }
    let duration = start.elapsed();
    println!(
        "{} states, {} iterations in {:.3}s\n    -> {: >10.3} M states/sec\n    -> {: >10.3} M iters/sec",
        test_mem,
        tot_counts,
        duration.as_secs_f64(),
        test_mem as f64 / duration.as_secs_f64() / 1_000_000.0,
        tot_counts as f64 / duration.as_secs_f64() / 1_000_000.0
    );

    println!(
        "Testing all programs would take {:.1}m, {:.1}h, {:.1}d, {:.1}w, {:.1}m",
        duration.as_secs_f64() / test_mem as f64 * max_mem as f64 / 60.0,
        duration.as_secs_f64() / test_mem as f64 * max_mem as f64 / 60.0 / 60.0,
        duration.as_secs_f64() / test_mem as f64 * max_mem as f64 / 60.0 / 60.0 / 24.0,
        duration.as_secs_f64() / test_mem as f64 * max_mem as f64 / 60.0 / 60.0 / 24.0 / 7.0,
        duration.as_secs_f64() / test_mem as f64 * max_mem as f64 / 60.0 / 60.0 / 24.0 / 30.0
    );

    println!();
    println!(
        "{} with mem {:?}, tried {} mems",
        cur_max, cur_max_mem, max_mem
    );
    for v in cur_max_mem.iter() {
        print!("{:02x}", v);
    }

    println!();
    println!("Loop {} with mem {:?},", cur_max_loop, cur_max_loop_mem,);
    for v in cur_max_loop_mem.iter() {
        print!("{:02x}", v);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn run_mem(mem_str: &str) -> usize {
        let mem_raw = hex_str_to_mem(mem_str).unwrap();
        let s = State::new_raw(mem_raw);

        let mut states = HashSet::new();
        s.iter_until_halt_or_loop(&mut states).unwrap()
    }

    fn hex_str_to_mem(s: &str) -> Result<[usize; N_LOCS], ()> {
        if s.len() != N_LOCS * 2 {
            return Err(());
        }

        let mut mem_raw = [0; N_LOCS];
        for i in 0..N_LOCS {
            mem_raw[i] = usize::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        Ok(mem_raw)
    }

    #[test]
    fn test_known_values() {
        // gethered directly from website
        let vals = if N_BITS == 2 {
            vec![
                ("205e4196", 170),
                ("318f3e4a", 611),
                ("72293041", 213),
                ("33567049", 342),
                ("6248238d", 808),
                ("62f12181", 769),
                ("275e419e", 114),
            ]
        } else if N_BITS == 3 {
            vec![
                ("3101703173317547", 2821),
                ("00000000000000ff", 8),
                ("3101703173317547", 2821),
                ("3101703173317547", 2821),
            ]
        } else if N_BITS == 4 {
            vec![
                ("00011a208d314a1c2b60ff6000ffe04c", 2556),
                ("000000000000000000000000000000ff", 16),
                ("00011a208d314a1c2b6eff0200ffe04c", 3066),
                ("00011a208d314a1c2b6e050500f0e04c", 66),
            ]
        } else {
            vec![]
        };

        for (mem_str, count) in vals {
            println!("Mem: {}", mem_str);
            assert_eq!(count, run_mem(mem_str));
        }
    }
}
