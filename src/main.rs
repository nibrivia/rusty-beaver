use std::u8;

const N_BITS: u8 = 2;
const N_LOCS: usize = 1 << N_BITS;

/// All the possible ops
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
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
type Command = (Op, i8);

fn op_from_mem(byte: u8) -> Op {
    //println!("op_from_mem: {}", byte);
    let r = match byte >> 4 {
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
    };
    //println!("op_from_mem: {:?}", r);
    r
}

//fn command_to_u8(cmd: Command) -> u8 {
//    (cmd.0 as u8) << 4 + cmd.1
//}

fn u8_to_command(byte: u8) -> Command {
    (op_from_mem(byte), (byte & 0x0F) as i8)
}

#[derive(Debug)]
struct State {
    mem: [u8; N_LOCS],

    pc: u8,
    a: u8,
    carry: bool,
    zero: bool,
}

impl State {
    pub fn new_raw(u8_mem: [u8; N_LOCS]) -> Result<State, ()> {
        Ok(State {
            pc: 0,
            a: 0,
            mem: u8_mem,
            carry: false,
            zero: true,
        })
    }

    /// Returns the next state
    pub fn next_state(self: &Self) -> Result<State, ()> {
        if self.pc >= N_LOCS as u8 {
            return Err(());
        }

        let mut pc = self.pc;
        let mut a = self.a;
        let mut mem = self.mem;
        let mut carry = self.carry;
        let mut zero = self.zero;

        let (op, operand) = u8_to_command(mem[pc as usize]);
        pc += 1;

        match op {
            Op::NOP => (),
            Op::LDA => a = mem[operand as usize % N_LOCS],
            Op::ADD => {
                let _a: usize = a as usize + mem[operand as usize % N_LOCS] as usize;
                carry = _a > 255;
                a = (_a % 256) as u8;
                zero = a == 0;
            }

            Op::SUB => {
                let _a: usize = a as usize + 256 - mem[operand as usize % N_LOCS] as usize;
                carry = _a > 255;
                a = (_a % 256) as u8;
                zero = a == 0;
            }
            Op::STA => mem[operand as usize % N_LOCS] = a as u8,
            Op::LDI => a = operand as u8,
            Op::JMP => pc = operand as u8,
            Op::JC => {
                if carry {
                    pc = operand as u8
                }
            }
            Op::JZ => {
                if zero {
                    pc = operand as u8
                }
            }
            Op::NINE | Op::A | Op::B | Op::C | Op::D | Op::OUT => (),
            Op::HLT => return Err(()),
        }

        //let a = (a % (1 << 8)) as i8;
        let pc = pc % N_LOCS as u8;
        Ok(State {
            pc,
            a,
            mem,
            carry,
            zero,
        })
    }
}

fn hex_str_to_mem(s: &str) -> Result<[u8; N_LOCS], ()> {
    if s.len() != N_LOCS * 2 {
        return Err(());
    }

    let mut mem_raw = [0, 0, 0, 0];
    for i in 0..N_LOCS {
        mem_raw[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    Ok(mem_raw)
}

fn run_mem(mem_str: &str) -> usize {
    let mem_raw = hex_str_to_mem(mem_str).unwrap();
    let mut s = State::new_raw(mem_raw).unwrap();

    let mut count = 1;
    loop {
        //println!("\n#{} {:?}", count, s);
        let ns = s.next_state();
        match ns {
            Ok(ns_safe) => {
                s = ns_safe;
                count += 1
            }
            Err(_) => break,
        };
        if count > 8000 {
            break;
        }
    }
    count
}

fn main() {
    let c = run_mem("205e4196");
    println!("{}", c);
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_known_values() {
        let vals = vec![
            ("205e4196", 170),
            ("318f3e4a", 611),
            ("72293041", 213),
            ("33567049", 342),
            ("6248238d", 808),
            ("62f12181", 769),
            ("275e419e", 114),
        ];

        for (mem_str, count) in vals {
            assert_eq!(count, run_mem(mem_str));
        }
    }
}
