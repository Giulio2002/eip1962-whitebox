#[macro_use] extern crate honggfuzz;

extern crate eth_pairings;
extern crate hex;

/*trait Fuzzer {
    fn fuzz(bytes: &[u8]) -> Result<(), eth_pairings::public_interface::ApiError>;
}

fn sqrt_for_three_mod_four<'a, E: eth_pairings::representation::ElementRepr, F: eth_pairings::field::SizedPrimeField<Repr = E>>(element: &eth_pairings::fp::Fp<'a, E, F>) -> Result<eth_pairings::fp::Fp<'a, E, F>, eth_pairings::public_interface::ApiError> {
    // this is a simple case: we compute the power 
    // we know that it's 3 mod 4, so just bit shift

    let mut modulus_minus_three_by_four = *element.field.modulus();
    modulus_minus_three_by_four.shr(2);

    let mut a = element.pow(&modulus_minus_three_by_four.as_ref());

    let mut minus_one = eth_pairings::fp::Fp::one(element.field);
    minus_one.negate();

    let mut tmp = a.clone();
    tmp.square();
    tmp.mul_assign(&element);

    if tmp == minus_one {
        panic!("not 3 mod 4");
    } else {
        a.mul_assign(&element);

        Ok(a)
    }
}

fn sqrt<'a, E: eth_pairings::representation::ElementRepr, F: eth_pairings::field::SizedPrimeField<Repr = E>>(element: &eth_pairings::fp::Fp<'a, E, F>) -> Result<eth_pairings::fp::Fp<'a, E, F>, eth_pairings::public_interface::ApiError> {
    if eth_pairings::square_root::modulus_is_three_mod_four(element.field) {
        sqrt_for_three_mod_four(&element)
    } else {
        panic!("Not 3 mod 4")
    }
}

macro_rules! expand_for_modulus_limbs {
    ($modulus_limbs: expr, $implementation: tt, $argument: expr, $func: tt) => {
        match $modulus_limbs {
            4 => {
                $implementation::<eth_pairings::field::U256Repr>::$func(&$argument)
            },
            5 => {
                $implementation::<eth_pairings::field::U320Repr>::$func(&$argument)
            },
            6 => {
                $implementation::<eth_pairings::field::U384Repr>::$func(&$argument)
            },
            7 => {
                $implementation::<eth_pairings::field::U448Repr>::$func(&$argument)
            },
            8 => {
                $implementation::<eth_pairings::field::U512Repr>::$func(&$argument)
            },
            9 => {
                $implementation::<eth_pairings::field::U576Repr>::$func(&$argument)
            },
            10 => {
                $implementation::<eth_pairings::field::U640Repr>::$func(&$argument)
            },
            11 => {
                $implementation::<eth_pairings::field::U704Repr>::$func(&$argument)
            },
            12 => {
                $implementation::<eth_pairings::field::U768Repr>::$func($argument)
            },
            13 => {
                $implementation::<eth_pairings::field::U832Repr>::$func(&$argument)
            },
            14 => {
                $implementation::<eth_pairings::field::U896Repr>::$func(&$argument)
            },
            15 => {
                $implementation::<eth_pairings::field::U960Repr>::$func(&$argument)
            },
            16 => {
                $implementation::<eth_pairings::field::U1024Repr>::$func($argument)
            },

            field_limbs => {
                unimplemented!("unimplemented for {} modulus limbs", field_limbs);
            }
        }
    }
}

pub struct Fuzz<FE: eth_pairings::representation::ElementRepr> {
    _marker_fe: std::marker::PhantomData<FE>,
}

impl<FE: eth_pairings::representation::ElementRepr> Fuzzer for Fuzz<FE> {
    
    fn fuzz(bytes: &[u8]) -> Result<(), eth_pairings::public_interface::ApiError> {
        let data = &bytes[1..];
        let (field, modulus_len, _, rest) = eth_pairings::public_interface::decode_fp::parse_base_field_from_encoding::<FE>(&data)?;
        let (a, b, rest) = eth_pairings::public_interface::decode_g1::parse_ab_in_base_field_from_encoding(&rest, 1, &field)?;
        let (_order_len, order, rest) = eth_pairings::public_interface::decode_g1::parse_group_order_from_encoding(rest)?;
        let fp_params = eth_pairings::weierstrass::CurveOverFpParameters::new(&field);
        let curve = eth_pairings::weierstrass::curve::WeierstrassCurve::new(&order.as_ref(), a, b, &fp_params).map_err(|_| {
            panic!("Curve shape is not supported")
        })?;
        // Point 0
        let (x_0, rest) = eth_pairings::public_interface::decode_fp::decode_fp(data, modulus_len, curve.params.params())?;
        let mut y_0 = curve.b.clone();
        let mut ax = x_0.clone();
        ax.mul_assign(&curve.a);
        y_0.add_assign(&ax);

        let mut x_3 = x_0.clone();
        x_3.square();
        x_3.mul_assign(&x_0);
        y_0.add_assign(&x_3);
        y_0 = sqrt(&y_0.clone())?;

        let p_0 = eth_pairings::weierstrass::curve::CurvePoint::point_from_xy(&curve, x_0, y_0);
        // Point 1
        let (x_1, rest) = eth_pairings::public_interface::decode_fp::decode_fp(data, modulus_len, curve.params.params())?;
        let mut y_1 = curve.b.clone();
        ax = x_1.clone();
        ax.mul_assign(&curve.a);
        y_1.add_assign(&ax);

        x_3 = x_1.clone();
        x_3.square();
        x_3.mul_assign(&x_1);
        y_1.add_assign(&x_3);
        y_1 = sqrt(&y_1.clone())?;
        let p_1 = eth_pairings::weierstrass::curve::CurvePoint::point_from_xy(&curve, x_1, y_1);
        // Point 2
        let (x_2, rest) = eth_pairings::public_interface::decode_fp::decode_fp(data, modulus_len, curve.params.params())?;
        let mut y_2 = curve.b.clone();
        ax = x_2.clone();
        ax.mul_assign(&curve.a);
        y_2.add_assign(&ax);

        x_3 = x_2.clone();
        x_3.square();
        x_3.mul_assign(&x_2);
        y_2.add_assign(&x_3);
        y_2 = sqrt(&y_1.clone())?;
        let p_2 = eth_pairings::weierstrass::curve::CurvePoint::point_from_xy(&curve, x_2, y_2);
        
        Ok(())
    }
}

pub struct FuzzG1Api;

impl Fuzzer for FuzzG1Api {
    fn fuzz(bytes: &[u8]) -> Result<(), eth_pairings::public_interface::ApiError> {
        let (_, modulus, _) = eth_pairings::public_interface::decode_utils::parse_modulus_and_length(&bytes)?;
        let modulus_limbs = eth_pairings::public_interface::decode_utils::num_limbs_for_modulus(&modulus)?;

        expand_for_modulus_limbs!(modulus_limbs, Fuzz, bytes, fuzz); 

        Ok(())
    }
}*/

fn main() {
    // Here you can parse `std::env::args and 
    // setup / initialize your project

    // You have full control over the loop but
    // you're supposed to call `fuzz` ad vitam aeternam
    loop {
        // The fuzz macro gives an arbitrary object (see `arbitrary crate`)
        // to a closure-like block of code.
        // For performance reasons, it is recommended that you use the native type
        // `&[u8]` when possible.
        // Here, this slice will contain a "random" quantity of "random" data.
        fuzz!(|data: &[u8]| {
            // TODO Unpack data into modulus, [field]Maybe, a, b, [curve], [p_1], [p_2], [p_3] XXXXX
            // TODO Test Associativity (A+B)+C = A+(B+C)
            // TODO Test Commutativity A+B+C=B+A+C
            eth_pairings::fuzz::run(data);
        });
    }
}