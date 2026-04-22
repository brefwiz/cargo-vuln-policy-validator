use crate::domain::models::Violation;

pub trait Reporter {
    fn report(&self, violations: &[Violation]);
}
