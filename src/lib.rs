use core::ops::Add;

/// Represents a point on an elliptic curve.
/// We could make the curse a generic parameter?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Point {
    a: i64,
    b: i64,
    x: Option<i64>,
    y: Option<i64>,
}

impl Point {
    /// Created a new `Point`
    pub fn new(a: i64, b: i64, x: Option<i64>, y: Option<i64>) -> Result<Self, PointError> {
        // This represents that the point is the identity point and we just return it, without
        // checking it's presence on the curve
        if x.is_none() && y.is_none() {
            return Ok(Self {
                a,
                b,
                x: None,
                y: None,
            });
        }

        // At this point it is safe to unwrap
        let (x, y) = (x.unwrap(), y.unwrap());

        // If the point is not on the curve, there is no reason to continue, at least for the scope
        // of this small library
        if y.pow(2) != x.pow(3) + a * x + b {
            return Err(PointError::NotOnCurve(a, b, x, y));
        }

        Ok(Self {
            a,
            b,
            x: Some(x),
            y: Some(y),
        })
    }
}

impl Add for Point {
    type Output = Result<Self, PointError>;

    fn add(self, other: Self) -> Self::Output {
        // Check if the 2 points are on the same curve
        if self.a != other.a || self.b != other.b {
            return Err(PointError::DifferentCurves(self.a, self.b, other.a, other.b));
        }

        // If `self` is point at infinity, we return the `other` element
        if self.x.is_none() && self.y.is_none() {
            return Ok(other);
        }

        // If `other` is point at infinity, we return the `self` element
        if other.x.is_none() && other.y.is_none() {
            return Ok(self);
        }

        // Just to be more paranoid about unwrapping `None`
        assert_ne!(self.x, None);
        assert_ne!(self.y, None);
        assert_ne!(other.x, None);
        assert_ne!(other.y, None);

        // At this point, we know that no value is `None`
        // We check if the 2 points represent a vertical line
        if self.x == other.x && (self.y.unwrap() + other.y.unwrap()) == 0 {
            // If yes, we return the point at infinity
            return Point::new(self.a, self.b, None, None);
        }

        panic!("Not implemented");
    }
}

#[derive(Debug)]
pub enum PointError {
    NotOnCurve(i64, i64, i64, i64),
    DifferentCurves(i64, i64, i64, i64),
}

#[cfg(test)]
mod tests {
    use super::Point;

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

        for (x,y) in pairs {
            if let Ok(_) = Point::new(a, b, Some(x), Some(y)) {
                println!("Point ({}, {}) IS on curve", x, y);
            } else {
                println!("Point ({}, {}) is NOT on curve", x, y);
            }
        }
    }

    #[test]
    fn test_addition() {
        // These 2 points represent a vertical line
        let p1 = Point::new(5, 7, Some(-1), Some(-1)).unwrap();
        let p2 = Point::new(5, 7, Some(-1), Some(1)).unwrap();

        let infinity = Point::new(5, 7, None, None).unwrap();
        assert_eq!((p1 + infinity).unwrap(), Point::new(5, 7, Some(-1), Some(-1)).unwrap());
        assert_eq!((p2 + infinity).unwrap(), Point::new(5, 7, Some(-1), Some(1)).unwrap());
        assert_eq!((p1 + p2).unwrap(), Point::new(5, 7, None, None).unwrap());
    }
}
