//! `PyO3` bindings.
//!
//! Exposes `Engine`, `Ring`, and `verify_ed25519` to Python.

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;

use crate::{verify_ed25519 as rust_verify, Engine as RustEngine, EngineConfig, Ring as RustRing};

#[pyclass(name = "Engine")]
struct PyEngine {
    inner: RustEngine,
}

#[pymethods]
impl PyEngine {
    #[new]
    fn new() -> Self {
        Self {
            inner: RustEngine::new(EngineConfig::default()),
        }
    }

    fn evaluate(&self, ring: &str, action_class: &str) -> PyResult<bool> {
        let r = match ring {
            "R0" => RustRing::R0Trusted,
            "R1" => RustRing::R1Namespaced,
            "R2" => RustRing::R2MicroVm,
            "R3" => RustRing::R3NetworkOnly,
            other => return Err(PyValueError::new_err(format!("unknown ring: {other}"))),
        };
        match self.inner.evaluate(r, action_class) {
            Ok(result) => Ok(result.allowed),
            Err(e) => Err(PyRuntimeError::new_err(e.to_string())),
        }
    }
}

#[pyfunction]
fn verify_ed25519(public_key: &[u8], message: &[u8], signature: &[u8]) -> PyResult<bool> {
    let pk: &[u8; 32] = public_key
        .try_into()
        .map_err(|_| PyValueError::new_err("public_key must be 32 bytes"))?;
    let sig: &[u8; 64] = signature
        .try_into()
        .map_err(|_| PyValueError::new_err("signature must be 64 bytes"))?;
    Ok(rust_verify(pk, message, sig).is_ok())
}

#[pymodule]
fn sentinel_engine(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyEngine>()?;
    m.add_function(wrap_pyfunction!(verify_ed25519, m)?)?;
    Ok(())
}
