use crate::domain::models::Violation;
use crate::ports::outbound::Reporter;

pub struct StdoutReporter;

impl Reporter for StdoutReporter {
    fn report(&self, violations: &[Violation]) {
        println!("\n❌ Policy validation failed:\n");

        for v in violations {
            println!(" - {}: {}", v.id, v.message);
            println!(
                "   ↳ {}:{}:{}",
                v.primary_span.path, v.primary_span.line, v.primary_span.column
            );
            println!("   ↳ {}", v.edit_hint());

            for related in &v.related_spans {
                println!(
                    "   ↳ related: {}:{}:{}",
                    related.path, related.line, related.column
                );
            }
        }
    }
}
