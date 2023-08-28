pub mod curve;
pub mod hashing;
pub mod serialise;
pub mod sign;

#[cfg(test)]
mod tests {
    use crate::curve::{Point, Secp256K1Point};
    use crate::hashing::double_sha256;
    use crate::sign::{PrivateKey, Signature};
    use finite_field::FieldElement;
    use primitive_types::U256;

    #[test]
    fn test_eq() {
        let a = Point::new(5, 7, Some(-1), Some(-1)).unwrap();
        let b = Point::new(5, 7, Some(-1), Some(-1)).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn test_ne() {
        let a = Point::new(5, 7, Some(-1), Some(-1)).unwrap();
        let b = Point::new(5, 7, Some(18), Some(77)).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn test_exercise1() {
        let a = 5;
        let b = 7;
        let pairs = [(2, 4), (-1, -1), (18, 77), (5, 7)];
        let not_on_curve = [(2, 4), (5, 7)];

        for (x, y) in pairs {
            if not_on_curve.contains(&(x, y)) {
                assert_eq!(false, Point::new(a, b, Some(x), Some(y)).is_ok());
            } else {
                assert_eq!(true, Point::new(a, b, Some(x), Some(y)).is_ok());
            }
        }
    }

    #[test]
    fn test_addition() {
        // These 2 points represent a vertical line
        let p1 = Point::new(5, 7, Some(-1), Some(-1)).unwrap();
        let p2 = Point::new(5, 7, Some(-1), Some(1)).unwrap();

        let infinity = Point::new(5, 7, None, None).unwrap();
        assert_eq!(
            (p1 + infinity).unwrap(),
            Point::new(5, 7, Some(-1), Some(-1)).unwrap()
        );
        assert_eq!(
            (p2 + infinity).unwrap(),
            Point::new(5, 7, Some(-1), Some(1)).unwrap()
        );
        assert_eq!((p1 + p2).unwrap(), Point::new(5, 7, None, None).unwrap());
    }

    #[test]
    fn exercise5() {
        let p1 = Point::new(5, 7, Some(2), Some(5)).unwrap();
        let p2 = Point::new(5, 7, Some(-1), Some(-1)).unwrap();

        let p3 = Point::new(5, 7, Some(3), Some(-7)).unwrap();

        assert_eq!((p1 + p2).unwrap(), p3);
    }

    #[test]
    fn exercise6() {
        let p1 = Point::new(5, 7, Some(-1), Some(-1)).unwrap();
        let p2 = p1;

        let p3 = Point::new(5, 7, Some(18), Some(77)).unwrap();

        assert_eq!((p1 + p2).unwrap(), p3);
    }

    // The following tests are for FieldElement testing
    #[test]
    fn elliptic_curve_over_finite_fields_exercise1() {
        let a = FieldElement::<i64>::new(0, 223).unwrap();
        let b = FieldElement::<i64>::new(7, 223).unwrap();

        let coordinates = [(192, 105), (17, 56), (200, 119), (1, 193), (42, 99)];
        let valid_points = [(192, 105), (17, 56), (1, 193)];

        for (x, y) in coordinates {
            let x1 = FieldElement::<i64>::new(x, 223).unwrap();
            let y1 = FieldElement::<i64>::new(y, 223).unwrap();
            let p1 = Point::new(a, b, Some(x1), Some(y1));

            if p1.is_ok() {
                assert!(valid_points.contains(&(x, y)));
            } else {
                assert!(!valid_points.contains(&(x, y)));
            }
        }
    }

    #[test]
    fn elliptic_curve_over_finite_fields_exercise2() {
        let a = FieldElement::<i64>::new(0, 223).unwrap();
        let b = FieldElement::<i64>::new(7, 223).unwrap();

        let point_pairs = [
            ((192, 105), (17, 56), (170, 142)),
            ((170, 142), (60, 139), (220, 181)),
            ((47, 71), (17, 56), (215, 68)),
            ((143, 98), (76, 66), (47, 71)),
        ];

        for ((x1, y1), (x2, y2), (x3, y3)) in point_pairs {
            let x1 = FieldElement::<i64>::new(x1, 223).unwrap();
            let y1 = FieldElement::<i64>::new(y1, 223).unwrap();

            let x2 = FieldElement::<i64>::new(x2, 223).unwrap();
            let y2 = FieldElement::<i64>::new(y2, 223).unwrap();

            let x3 = FieldElement::<i64>::new(x3, 223).unwrap();
            let y3 = FieldElement::<i64>::new(y3, 223).unwrap();

            let p1 = Point::new(a, b, Some(x1), Some(y1)).unwrap();
            let p2 = Point::new(a, b, Some(x2), Some(y2)).unwrap();
            let p3 = Point::new(a, b, Some(x3), Some(y3)).unwrap();

            assert_eq!((p1 + p2).unwrap(), p3);
        }
    }

    #[test]
    fn elliptic_curve_over_finite_fields_exercise4() {
        let a = FieldElement::<i64>::new(0, 223).unwrap();
        let b = FieldElement::<i64>::new(7, 223).unwrap();
        let x1 = FieldElement::<i64>::new(47, 223).unwrap();
        let y1 = FieldElement::<i64>::new(71, 223).unwrap();

        let p1 = Point::new(a, b, Some(x1), Some(y1)).unwrap();

        let finite_group_pairs = [
            (47, 71),
            (36, 111),
            (15, 137),
            (194, 51),
            (126, 96),
            (139, 137),
            (92, 47),
            (116, 55),
            (69, 86),
            (154, 150),
            (154, 73),
            (69, 137),
            (116, 168),
            (92, 176),
            (139, 86),
            (126, 127),
            (194, 172),
            (15, 86),
            (36, 112),
            (47, 152),
        ];

        for s in 1..21 {
            let (x, y) = finite_group_pairs.get(s - 1).unwrap();

            let x3 = FieldElement::<i64>::new(*x, 223).unwrap();
            let y3 = FieldElement::<i64>::new(*y, 223).unwrap();

            let p3 = (p1 * s as u32).unwrap();
            let p_result = Point::new(a, b, Some(x3), Some(y3)).unwrap();

            assert_eq!(p3, p_result);
        }
    }

    // TODO: Make a test to challenge the assertions made at page 51 by repeateadly substracting
    // the element from the left side of the equation to the element on the right side of the
    // equation
    #[test]
    fn test_reverse_scalar_multiplication() {
        let a = FieldElement::<i64>::new(0, 223).unwrap();
        let b = FieldElement::<i64>::new(7, 223).unwrap();
        let x1 = FieldElement::<i64>::new(47, 223).unwrap();
        let y1 = FieldElement::<i64>::new(71, 223).unwrap();
        let p_base = Point::new(a, b, Some(x1), Some(y1)).unwrap();

        let a = FieldElement::<i64>::new(0, 223).unwrap();
        let b = FieldElement::<i64>::new(7, 223).unwrap();
        let x2 = FieldElement::<i64>::new(47, 223).unwrap();
        let y2 = FieldElement::<i64>::new(71, 223).unwrap();
        let y_zero = FieldElement::<i64>::new(0, 223).unwrap();
        let p_to_sub = Point::new(a, b, Some(x2), Some(y_zero - y2)).unwrap();

        let a = FieldElement::<i64>::new(0, 223).unwrap();
        let b = FieldElement::<i64>::new(7, 223).unwrap();
        let x_res = FieldElement::<i64>::new(194, 223).unwrap();
        let y_res = FieldElement::<i64>::new(172, 223).unwrap();
        let p_res = Point::new(a, b, Some(x_res), Some(y_res)).unwrap();

        let mut times = 1;
        let mut p_right = p_res;

        // When should it finish if it does not have a solution?
        while p_right != p_base {
            p_right = (p_right + p_to_sub).unwrap();
            times += 1;
        }

        assert_eq!(17, times);
    }

    // Essentially this test if for making sure that the generator is on the curve
    #[test]
    fn test_seckp256k1field_new() {
        Secp256K1Point::generator().unwrap();
    }

    // Verify whether the generator point, G, has the order n
    #[test]
    fn test_seckp256k1_generator_has_order_n() {
        let generator_point = Secp256K1Point::generator().expect("Failed to get generator");
        // N represents the order of the group
        let n: U256 = U256::from_str_radix(
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
            16,
        )
        .unwrap();
        // X and Y of this point should be `None`
        let _point_at_infinity = (generator_point * n).expect("Failed to multiply");
    }

    #[test]
    fn test_verify_signature() {
        let z = U256::from_str_radix(
            "bc62d4b80d9e36da29c16c5d4d9f11731f36052c72401a76c23c0fb5a9b74423",
            16,
        )
        .unwrap();
        let r = U256::from_str_radix(
            "37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6",
            16,
        )
        .unwrap();
        let s = U256::from_str_radix(
            "8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec",
            16,
        )
        .unwrap();
        let px = U256::from_str_radix(
            "04519fac3d910ca7e7138f7013706f619fa8f033e6ec6e09370ea38cee6a7574",
            16,
        )
        .unwrap();
        let py = U256::from_str_radix(
            "82b51eab8c27c66e26c858a079bcdf4f1ada34cec420cafc7eac1a42216fb6c4",
            16,
        )
        .unwrap();

        let point = Secp256K1Point::new(px, py).unwrap();

        assert!(point.verify(z, Signature::new(r, s)).unwrap() == true);
    }

    #[test]
    fn test_verify_signature_exercise6() {
        let px = U256::from_str_radix(
            "887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c",
            16,
        )
        .unwrap();
        let py = U256::from_str_radix(
            "61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34",
            16,
        )
        .unwrap();
        let point = Secp256K1Point::new(px, py).unwrap();

        let pairs = [
            (
                "ec208baa0fc1c19f708a9ca96fdeff3ac3f230bb4a7ba4aede4942ad003c0f60",
                "ac8d1c87e51d0d441be8b3dd5b05c8795b48875dffe00b7ffcfac23010d3a395",
                "68342ceff8935ededd102dd876ffd6ba72d6a427a3edb13d26eb0781cb423c4",
            ),
            (
                "7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d",
                "eff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c",
                "c7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab6",
            ),
        ];

        for (z, r, s) in pairs.iter() {
            let z = U256::from_str_radix(z, 16).unwrap();
            let r = U256::from_str_radix(r, 16).unwrap();
            let s = U256::from_str_radix(s, 16).unwrap();

            assert!(point.verify(z, Signature::new(r, s)).unwrap() == true);
        }
    }

    #[test]
    fn test_sign_with_private_key() {
        let secret = U256::from_str_radix(
            "f8b8af8ce3c7cca5e300d33939540c10d45ce001b8f252bfbc57ba0342904181",
            16,
        )
        .unwrap();
        let priv_key = PrivateKey::new(secret).expect("Bad Private Key");
        let message = double_sha256(b"Alan Turing");

        assert_eq!(
            true,
            priv_key
                .point()
                .verify(message, priv_key.sign(message).unwrap())
                .unwrap(),
        );
    }

    #[test]
    fn test_create_signature() {
        // This is an example of a brain wallet. This is a way to keep the private key, or rather
        // the stem or seed of the private key in your head without having to memorize something
        // too difficult.
        // TO NOT BE USED as a REAL SECRET.
        let e = double_sha256(b"my secret");
        // This is the signature hash, or the hash of the message that we are signing.
        let z = double_sha256(b"my message");

        // This is just for testing purposes
        let z_from_str = U256::from_str_radix(
            "231c6f3d980a6b0fb7152f85cee7eb52bf92433d9919b9c5218cb08e79cce78",
            16,
        )
        .unwrap();

        assert_eq!(z, z_from_str);

        // We are going to use a fixed `k` here, as a random value, for demonstration purposes.
        let k = U256::from(1234567890u64);

        // Fetch the generator point from the Bitcoin curve
        let generator = Secp256K1Point::generator().unwrap();

        // Compute the x-coordinate of R, which is k*G
        let r = (generator * k).unwrap().point().x().unwrap().value;
        let r_from_str = U256::from_str_radix(
            "2b698a0f0a4041b77e63488ad48c23e8e8838dd1fb7520408b121697b782ef22",
            16,
        )
        .unwrap();
        assert_eq!(r_from_str, r);

        // Compute s=(z+r*e)/k
        use crate::curve::pow_mod;
        use finite_field::Element;
        let k_inv = pow_mod(k, generator.order() - U256::from(2u8), generator.order());

        let s = (z + r.mul_mod(e, generator.order())).mul_mod(k_inv, generator.order());
        let s_from_str = U256::from_str_radix(
            "bb14e602ef9e3f872e25fad328466b34e6734b7a0fcd58b1eb635447ffae8cb9",
            16,
        )
        .unwrap();
        assert_eq!(s_from_str, s);

        let point = (generator * e).unwrap();

        // Verifiy the signature that we got with the public key
        assert_eq!(true, point.verify(z, Signature::new(r, s)).unwrap());

        let point = point.point();
        let px_from_str = U256::from_str_radix(
            "028d003eab2e428d11983f3e97c3fa0addf3b42740df0d211795ffb3be2f6c52",
            16,
        )
        .unwrap();
        let py_from_str = U256::from_str_radix(
            "0ae987b9ec6ea159c78cb2a937ed89096fb218d9e7594f02b547526d8cd309e2",
            16,
        )
        .unwrap();
        assert_eq!(px_from_str, point.x().unwrap().value);
        assert_eq!(py_from_str, point.y().unwrap().value);
    }

    #[test]
    fn test_uncompressed_sec() {
        let sec_pairs = [
            (U256::from(5000), "testdata/ex1_5000"),
            (U256::from(2018_u128.pow(5)), "testdata/ex1_2018_pow_5"),
            (
                U256::from_str_radix("deadbeef12345", 16).unwrap(),
                "testdata/ex1_deadbeef12345",
            ),
        ];

        for (secret, filename) in sec_pairs {
            let private_key = PrivateKey::new(secret).expect("Cannot make private key");
            let sec_form = std::fs::read(filename).unwrap();
            assert_eq!(
                private_key.point().sec(false).unwrap().as_slice(),
                sec_form.as_slice()
            );
        }
    }

    #[test]
    fn test_compressed_sec() {
        let sec_pairs = [
            (U256::from(5001), "testdata/ex2_5001"),
            (U256::from(2019_u128.pow(5)), "testdata/ex2_2019_pow_5"),
            (
                U256::from_str_radix("deadbeef54321", 16).unwrap(),
                "testdata/ex2_deadbeef54321",
            ),
        ];

        for (secret, filename) in sec_pairs {
            let private_key = PrivateKey::new(secret).expect("Cannot make private key");
            let sec_form = std::fs::read(filename).unwrap();
            assert_eq!(
                private_key.point().sec(true).unwrap().as_slice(),
                sec_form.as_slice()
            );
        }
    }

    #[test]
    fn test_signature() {
        let r = U256::from_str_radix(
            "0000000000000000000000000000000000000000000000000000001abcdef",
            16,
        )
        .unwrap();
        let s = U256::from_str_radix(
            "0000000000000000000000000000000000000000000000000000000abcdef",
            16,
        )
        .unwrap();

        let sig = Signature::new(r, s);
        sig.der().unwrap();
    }

    #[test]
    fn test_der_ex3() {
        let r = U256::from_str_radix(
            "37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6",
            16,
        )
        .unwrap();
        let s = U256::from_str_radix(
            "8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec",
            16,
        )
        .unwrap();

        let sig = Signature::new(r, s);
        // Encode our signature with the DER format
        let der_encoding = sig.der().unwrap();

        // Read the result from the test file
        let der_enc_result = std::fs::read("testdata/ex3_der_encoded_sig.bin").unwrap();

        // Test if the 2 are equal
        assert_eq!(der_encoding, der_enc_result,);
    }

    #[test]
    fn test_base58_ex4() {
        let values = [
            (
                "7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d",
                "testdata/base58_ex4_1.txt",
            ),
            (
                "eff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c",
                "testdata/base58_ex4_2.txt",
            ),
            (
                "c7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab6",
                "testdata/base58_ex4_3.txt",
            ),
        ];

        for (hex_value, file_path) in values.iter() {
            let value = U256::from_str_radix(hex_value, 16).unwrap();
            let base58_encoding = crate::serialise::_encode_base58(value).unwrap();
            let mut correct_value = std::fs::read_to_string(file_path).unwrap();
            correct_value.pop();
            assert_eq!(base58_encoding, correct_value);
        }
    }
}
