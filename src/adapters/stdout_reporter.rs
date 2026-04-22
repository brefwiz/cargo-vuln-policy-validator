use crate::domain::models::Violation;
use crate::ports::outbound::Reporter;

pub struct StdoutReporter;

impl Reporter for StdoutReporter {
    fn report(&self, violations: &[Violation]) {
        println!("\n❌ Policy validation failed:\n");

        for v in violations {
            match &v.source {
                Some(s) => {
                    println!(" - {}: {}\n   ↳ {}", v.id, v.message, s);
                }
                None => {
                    println!(" - {}: {}", v.id, v.message);
                }
            }
        }
    }
}
