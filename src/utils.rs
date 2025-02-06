use std::io::{Error, ErrorKind, Read, Result, Write};

use snark_verifier_sdk::snark_verifier::{
    halo2_base::utils::ScalarField, util::arithmetic::CurveAffine,
};

pub fn read_field_le<F: ScalarField>(reader: &mut impl Read) -> Result<F> {
    let mut repr = [0u8; 32];
    reader.read_exact(&mut repr)?;
    Ok(F::from_bytes_le(&repr))
}

pub fn read_curve_compressed<C: CurveAffine>(reader: &mut impl Read) -> Result<C> {
    let mut compressed = C::Repr::default();
    reader.read_exact(compressed.as_mut())?;
    Option::from(C::from_bytes(&compressed))
        .ok_or_else(|| Error::new(ErrorKind::Other, "Invalid compressed point encoding"))
}

pub fn write_field_le<F: ScalarField>(writer: &mut impl Write, fe: F) -> Result<()> {
    let repr = ScalarField::to_bytes_le(&fe);
    writer.write_all(&repr)?;
    Ok(())
}

pub fn write_curve_compressed<C: CurveAffine>(writer: &mut impl Write, point: C) -> Result<()> {
    let compressed = point.to_bytes();
    writer.write_all(compressed.as_ref())?;
    Ok(())
}
