#![deny(
    missing_docs,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications
)]
#![allow(dead_code)]
//!  This crate provides macros to generate bitfield-like struct.
//!
//!  See the documentation of the macros for how to use them.
//!
//!  Examples and tests are also a great way to understand how to use these macros.

/// Generates and dispatches trait implementations for a struct
///
/// This must be called outside of any `impl` block.
///
/// The syntax is `TheNameOfTheTrait for struct TheNameOfTheStruct(TheInnerType);` followed by the syntax of bitfield_fields.
///
/// Supported traits:
/// * Debug
/// * BitAnd
/// * BitOr
/// * BitXor
///
/// Additional derivations:
/// * new
///   * Creates a constructor, including parameters for all fields with a setter
/// * new{constructor_name(setter_name: setter_type, ...)}
///   * Creates a constructor using the given name and parameters. In order to compile correctly, each `setter_name`
///     must be the setter of a field of type `setter_type` specified later in the macro.
#[macro_export(local_inner_macros)]
macro_rules! bitfield_impl {
(Debug for struct $name:ident([$t:ty]); $($rest:tt)*) => {
    impl<T: AsRef<[$t]> + core::fmt::Debug> core::fmt::Debug for $name<T> {
        bitfield_debug!{struct $name; $($rest)*}
    }
};
(Debug for struct $name:ident($t:ty); $($rest:tt)*) => {
    impl core::fmt::Debug for $name {
        bitfield_debug!{struct $name; $($rest)*}
    }
};
(BitAnd for struct $name:ident([$t:ty]); $($rest:tt)*) => {
    bitfield_impl!{@bitwise BitAnd bitand BitAndAssign bitand_assign $name([$t]) &=}
};
(BitAnd for struct $name:ident($t:ty); $($rest:tt)*) => {
    bitfield_impl!{@bitwise BitAnd bitand BitAndAssign bitand_assign $name($t) &=}
};
(BitOr for struct $name:ident([$t:ty]); $($rest:tt)*) => {
    bitfield_impl!{@bitwise BitOr bitor BitOrAssign bitor_assign $name([$t]) |=}
};
(BitOr for struct $name:ident($t:ty); $($rest:tt)*) => {
    bitfield_impl!{@bitwise BitOr bitor BitOrAssign bitor_assign $name($t) |=}
};
(BitXor for struct $name:ident([$t:ty]); $($rest:tt)*) => {
    bitfield_impl!{@bitwise BitXor bitxor BitXorAssign bitxor_assign $name([$t]) ^=}
};
(BitXor for struct $name:ident($t:ty); $($rest:tt)*) => {
    bitfield_impl!{@bitwise BitXor bitxor BitXorAssign bitxor_assign $name($t) ^=}
};
(@bitwise $bitwise:ident $func:ident $bitwise_assign:ident $func_assign:ident $name:ident([$t:ty]) $op:tt) => {
    impl<T: AsMut<[$t]> + AsRef<[$t]>> crate::utils::bitfield::ops::$bitwise for $name<T> {
        type Output = Self;
        fn $func(mut self, rhs: Self) -> Self {
            bitfield_impl!(@mutate self rhs $op);
            self
        }
    }
    impl<T: AsMut<[$t]> + AsRef<[$t]>> crate::utils::bitfield::ops::$bitwise_assign for $name<T> {
        fn $func_assign(&mut self, rhs: Self) {
            bitfield_impl!(@mutate self rhs $op);
        }
    }
};
(@bitwise $bitwise:ident $func:ident $bitwise_assign:ident $func_assign:ident $name:ident($t:ty) $op:tt) => {
    impl crate::utils::bitfield::ops::$bitwise for $name {
        type Output = Self;
        fn $func(mut self, rhs: Self) -> Self {
            self.0 $op rhs.0;
            self
        }
    }
    impl crate::utils::bitfield::ops::$bitwise_assign for $name {
        fn $func_assign(&mut self, rhs: Self) {
            self.0 $op rhs.0;
        }
    }
};
(@mutate $self:ident $rhs:ident $op:tt) => {{
    let as_mut = AsMut::<[_]>::as_mut(&mut $self.0);
    let rhs = AsRef::<[_]>::as_ref(&$rhs.0);
    for i in 0..as_mut.len() {
        as_mut[i] $op rhs[i];
    }
}};
(new for struct $name:ident([$t:ty]); $($rest:tt)*) => {
    impl<T: AsMut<[$t]> + Default> $name<T> {
        bitfield_constructor!{() -> {}; $($rest)*}
    }
};
(new for struct $name:ident($t:ty); $($rest:tt)*) => {
    impl $name {
        bitfield_constructor!{() -> {}; $($rest)*}
    }
};
(new{$new:ident ($($setter_name:ident: $setter_type:ty),*$(,)?)} for struct $name:ident([$t:ty]); $($rest:tt)*) => {
    impl<T: AsMut<[$t]> + Default> $name<T> {
        pub fn $new($($setter_name: $setter_type),*) -> Self {
            let mut value = Self(T::default());
            $(
                value.$setter_name($setter_name);
            )*
            value
        }
    }
};
(new{$new:ident ($($setter_name:ident: $setter_type:ty),*$(,)?)} for struct $name:ident($t:ty); $($rest:tt)*) => {
    impl $name {
        pub fn $new($($setter_name: $setter_type),*) -> Self {
            let mut value = Self($t::default());
            $(
                value.$setter_name($setter_name);
            )*
            value
        }
    }
};
// display a more friendly error message when someone tries to use `impl <Trait>;` syntax when not supported
($macro:ident for struct $name:ident $($rest:tt)*) => {
    ::std::compile_error!(::std::stringify!(Unsupported impl $macro for struct $name));
};
}

/// Declares the fields of struct.
///
/// This macro will generate the methods to access the fields of a bitfield. It must be called
/// from an `impl` block for a type that implements the `BitRange` and/or the `Bit` traits
/// (which traits are required depending on what type of fields are used).
///
/// The syntax of this macro is composed of declarations ended by semicolons. There are two types
/// of declarations: default type, and fields.
///
/// A default type is just a type followed by a semicolon. This will affect all the following field
/// declarations.
///
/// A field declaration is composed of the following:
///
/// * Optional attributes (`#[...]`), documentation comments (`///`) are attributes;
/// * An optional pub keyword to make the methods public
/// * An optional type followed by a comma
/// * Optionally, the word `into` followed by a type, followed by a comma
/// * The getter and setter idents, separated by a comma
/// * A colon
/// * One to three expressions of type `usize`
///
/// The attributes and pub will be applied to the two methods generated.
///
/// If the `into` part is used, the getter will convert the field after reading it.
///
/// The getter and setter idents can be `_` to not generate one of the two. For example, if the
/// setter is `_`, the field will be read-only.
///
/// The expressions at the end are the bit positions. Their meaning depends on the number of
/// expressions:
///
///  * One expression: the field is a single bit. The type is ignored and `bool` is used. The trait
///    `Bit` is used.
///  * Two expressions: `msb, lsb`, the field is composed of the bits from `msb` to `lsb`, included.
///  * Three expressions: `msb, lsb, count`, the field is an array. The first element is composed of
///    the bits from `msb` to `lsb`. The following elements are consecutive bits range of the same
///    size.
///
/// # Example
///
/// ```rust
/// # #[macro_use] extern crate bitfield;
/// # fn main() {}
/// # struct FooBar(u64);
/// # bitfield_bitrange!{struct FooBar(u64)}
/// # impl From<u32> for FooBar{ fn from(_: u32) -> FooBar {unimplemented!()}}
/// # impl From<FooBar> for u32{ fn from(_: FooBar) -> u32 {unimplemented!()}}
/// # impl FooBar {
/// bitfield_fields!{
///     // The default type will be `u64
///     u64;
///     // filed1 is read-write, public, the methods are inline
///     #[inline]
///     pub field1, set_field1: 10, 0;
///     // `field2` is  read-only, private, and of type bool.
///     field2, _ : 0;
///     // `field3` will be read as an `u32` and then converted to `FooBar`.
///     // The setter is not affected, it still need an `u32` value.
///     u32, into FooBar, field3, set_field3: 10, 0;
///     // `field4` will be read as an `u32` and then converted to `FooBar`.
///     // The setter will take a `FooBar`, and converted back to an `u32`.
///     u32, from into FooBar, field4, set_field4: 10, 0;
///     // `field5` will be read as an `u32` and then converted to `FooBar`.
///     // The setter will take a `FooBar`, and converted back to an `u32`.
///     // The struct will have an associated constant `FIELD5_MASK` of type u64
///     //with the bits of field5 set
///     u32, mask FIELD5_MASK(u64), from into FooBar, field5, set_field5: 10, 0;
/// }
/// # }
/// ```
#[macro_export(local_inner_macros)]
macro_rules! bitfield_fields {
(only mask; @field $(#[$attribute:meta])* ($($vis:tt)*) $t:ty, $mask:ident($mask_t:ty), $from:ty, $into:ty, _, $setter:ident: $($exprs:expr),*) => {
    bitfield_fields!(only mask; @field $(#[$attribute])* ($($vis)*) $t, $mask($mask_t): $($exprs),*);
};
(only mask; @field $(#[$attribute:meta])* ($($vis:tt)*) $t:ty, $mask:ident($mask_t:ty), $from:ty, $into:ty, $getter:ident, _: $($exprs:expr),*) => {
    bitfield_fields!(only mask; @field $(#[$attribute])* ($($vis)*) $t, $mask($mask_t): $($exprs),*);
};
(only mask; @field $(#[$attribute:meta])* ($($vis:tt)*) $t:ty, __NO_MASK_FOR_FIELD($mask_t:ty): $($exprs:expr),*) => {};
(only mask; @field $(#[$attribute:meta])* ($($vis:tt)*) $t:ty, $mask:ident($mask_t:ty): $bit:expr) => {
    $($vis)* const $mask: $mask_t = 1 << $bit;
};
(only mask; @field $(#[$attribute:meta])* ($($vis:tt)*) $t:ty, $mask:ident($mask_t:ty): $msb:expr, $lsb:expr) => {
    $($vis)* const $mask: $mask_t = {
        let msb = $msb;
        let lsb = $lsb;
        let mut i = lsb;
        let mut acc = 0;
        while i <= msb {
            acc |= 1<<i;
            i += 1;
        }
        acc
    };
};
(only mask; @field $(#[$attribute:meta])* ($($vis:tt)*) $t:ty, $mask:ident($mask_t:ty): $msb:expr, $lsb:expr, $count:expr) => {
    $($vis)* const $mask: $mask_t = {
        let msb = $msb;
        let lsb = $lsb;
        let width = msb - lsb;
        let full_msb = msb + width * $count;
        let mut i = lsb;
        let mut acc = 0;
        while i <= full_msb {
            acc |= 1<<i;
            i += 1;
        }
        acc
    };
};
(only setter; @field $(#[$attribute:meta])* ($($vis:tt)*) $t:ty, $mask:ident($mask_t:ty), $from:ty, $into:ty, _, $setter:ident: $msb:expr,
    $lsb:expr, $count:expr) => {
    $(#[$attribute])*
    #[allow(unknown_lints)]
    #[allow(eq_op)]
    $($vis)* fn $setter(&mut self, index: usize, value: $from) {
        use crate::utils::bitfield::BitRangeMut;
        __bitfield_debug_assert!(index < $count);
        let width = $msb - $lsb + 1;
        let lsb = $lsb + index*width;
        let msb = lsb + width - 1;
        self.set_bit_range(msb, lsb, core::convert::Into::<$t>::into(value));
    }
};
(only setter; @field $(#[$attribute:meta])* ($($vis:tt)*) $t:ty, $mask:ident($mask_t:ty), $from:ty, $into:ty, _, $setter:ident: $msb:expr,
    $lsb:expr) => {
    $(#[$attribute])*
    $($vis)* fn $setter(&mut self, value: $from) {
        use crate::utils::bitfield::BitRangeMut;
        self.set_bit_range($msb, $lsb, core::convert::Into::<$t>::into(value));
    }
};
(only setter; @field $(#[$attribute:meta])* ($($vis:tt)*) $t:ty, $mask:ident($mask_t:ty), $from:ty, $into:ty, _, $setter:ident: $bit:expr) => {
    $(#[$attribute])*
    $($vis)* fn $setter(&mut self, value: bool) {
        use crate::utils::bitfield::BitMut;
        self.set_bit($bit, value);
    }
};
(only getter; @field $(#[$attribute:meta])* ($($vis:tt)*) $t:ty, $mask:ident($mask_t:ty), $from:ty, $into:ty, _, $setter:ident: $($exprs:expr),*) => {};

(only getter; @field $(#[$attribute:meta])* ($($vis:tt)*) $t:ty, $mask:ident($mask_t:ty), $from:ty, $into:ty, $getter:ident, _: $msb:expr, $lsb:expr, $count:expr) => {
    $(#[$attribute])*
    #[allow(unknown_lints)]
    #[allow(eq_op)]
    $($vis)* fn $getter(&self, index: usize) -> $into {
        use crate::utils::bitfield::BitRange;
        __bitfield_debug_assert!(index < $count);
        let width = $msb - $lsb + 1;
        let lsb = $lsb + index*width;
        let msb = lsb + width - 1;
        let raw_value: $t = self.bit_range(msb, lsb);
        core::convert::Into::into(raw_value)
    }
};
(only getter; @field $(#[$attribute:meta])* ($($vis:tt)*) $t:ty, $mask:ident($mask_t:ty), $from:ty, $into:ty, $getter:ident, _: $msb:expr,
    $lsb:expr) => {
    $(#[$attribute])*
    $($vis)* fn $getter(&self) -> $into {
        use crate::utils::bitfield::BitRange;
        let raw_value: $t = self.bit_range($msb, $lsb);
        core::convert::Into::into(raw_value)
    }
};
(only getter; @field $(#[$attribute:meta])* ($($vis:tt)*) $t:ty, $mask:ident($mask_t:ty), $from:ty, $into:ty, $getter:ident, _: $bit:expr) => {
    $(#[$attribute])*
    $($vis)* fn $getter(&self) -> bool {
        use crate::utils::bitfield::Bit;
        self.bit($bit)
    }
};
(only setter; @field $(#[$attribute:meta])* ($($vis:tt)*) $t:ty, $mask:ident($mask_t:ty), $from:ty, $into:ty, $getter:ident, _: $($exprs:expr),*) => {};

(only $only:tt; @field $(#[$attribute:meta])* ($($vis:tt)*) $t:ty, $mask:ident($mask_t:ty), $from:ty, $into:ty, $getter:ident, $setter:ident:
    $($exprs:expr),*) => {
    bitfield_fields!(only $only; @field $(#[$attribute])* ($($vis)*) $t, $mask($mask_t), $from, $into, $getter, _: $($exprs),*);
    bitfield_fields!(only $only; @field $(#[$attribute])* ($($vis)*) $t, __NO_MASK_FOR_FIELD(u8), $from, $into, _, $setter: $($exprs),*);
};

(only $only:tt; $t:ty;) => {};
(only $only:tt; $default_ty:ty; pub $($rest:tt)*) => {
    bitfield_fields!{only $only; $default_ty; () pub $($rest)*}
};

(only $only:tt; $default_ty:ty; #[$attribute:meta] $($rest:tt)*) => {
    bitfield_fields!{only $only; $default_ty; (#[$attribute]) $($rest)*}
};
(only $only:tt; $default_ty:ty; ($(#[$attributes:meta])*) #[$attribute:meta] $($rest:tt)*) => {
    bitfield_fields!{only $only; $default_ty; ($(#[$attributes])* #[$attribute]) $($rest)*}
};
(only $only:tt; $default_ty:ty; ($(#[$attribute:meta])*) pub $t:ty, mask $mask:ident($mask_t:ty), from into $into:ty, $getter:tt, $setter:tt:
    $($exprs:expr),*; $($rest:tt)*) => {
    bitfield_fields!{only $only; @field $(#[$attribute])* (pub) $t, $mask($mask_t), $into, $into, $getter, $setter: $($exprs),*}
    bitfield_fields!{only $only; $default_ty; $($rest)*}
};
(only $only:tt; $default_ty:ty; ($(#[$attribute:meta])*) pub $t:ty, mask $mask:ident($mask_t:ty), into $into:ty, $getter:tt, $setter:tt:
    $($exprs:expr),*; $($rest:tt)*) => {
    bitfield_fields!{only $only; @field $(#[$attribute])* (pub) $t, $mask($mask_t), $t, $into, $getter, $setter: $($exprs),*}
    bitfield_fields!{only $only; $default_ty; $($rest)*}
};
(only $only:tt; $default_ty:ty; ($(#[$attribute:meta])*) pub $t:ty, mask $mask:ident($mask_t:ty), $getter:tt, $setter:tt:  $($exprs:expr),*;
    $($rest:tt)*) => {
    bitfield_fields!{only $only; @field $(#[$attribute])* (pub) $t, $mask($mask_t), $t, $t, $getter, $setter: $($exprs),*}
    bitfield_fields!{only $only; $default_ty; $($rest)*}
};
(only $only:tt; $default_ty:ty; ($(#[$attribute:meta])*) pub mask $mask:ident($mask_t:ty), from into $into:ty, $getter:tt, $setter:tt:
    $($exprs:expr),*; $($rest:tt)*) => {
    bitfield_fields!{only $only; @field $(#[$attribute])* (pub) $default_ty, $mask($mask_t), $into, $into, $getter, $setter:
                        $($exprs),*}
    bitfield_fields!{only $only; $default_ty; $($rest)*}
};
(only $only:tt; $default_ty:ty; ($(#[$attribute:meta])*) pub mask $mask:ident($mask_t:ty), into $into:ty, $getter:tt, $setter:tt:
    $($exprs:expr),*; $($rest:tt)*) => {
    bitfield_fields!{only $only; @field $(#[$attribute])* (pub) $default_ty, $mask($mask_t), $default_ty, $into, $getter, $setter:
                        $($exprs),*}
    bitfield_fields!{only $only; $default_ty; $($rest)*}
};
(only $only:tt; $default_ty:ty; ($(#[$attribute:meta])*) pub mask $mask:ident($mask_t:ty), $getter:tt, $setter:tt:  $($exprs:expr),*;
    $($rest:tt)*) => {
    bitfield_fields!{only $only; @field $(#[$attribute])* (pub) $default_ty, $mask($mask_t), $default_ty, $default_ty, $getter, $setter:
                            $($exprs),*}
    bitfield_fields!{only $only; $default_ty; $($rest)*}
};

(only $only:tt; $default_ty:ty; ($(#[$attribute:meta])*) pub $t:ty, from into $into:ty, $getter:tt, $setter:tt:
    $($exprs:expr),*; $($rest:tt)*) => {
    bitfield_fields!{only $only; @field $(#[$attribute])* (pub) $t, __NO_MASK_FOR_FIELD(u8), $into, $into, $getter, $setter: $($exprs),*}
    bitfield_fields!{only $only; $default_ty; $($rest)*}
};
(only $only:tt; $default_ty:ty; ($(#[$attribute:meta])*) pub $t:ty, into $into:ty, $getter:tt, $setter:tt:
    $($exprs:expr),*; $($rest:tt)*) => {
    bitfield_fields!{only $only; @field $(#[$attribute])* (pub) $t, __NO_MASK_FOR_FIELD(u8), $t, $into, $getter, $setter: $($exprs),*}
    bitfield_fields!{only $only; $default_ty; $($rest)*}
};
(only $only:tt; $default_ty:ty; ($(#[$attribute:meta])*) pub $t:ty, $getter:tt, $setter:tt:  $($exprs:expr),*;
    $($rest:tt)*) => {
    bitfield_fields!{only $only; @field $(#[$attribute])* (pub) $t, __NO_MASK_FOR_FIELD(u8), $t, $t, $getter, $setter: $($exprs),*}
    bitfield_fields!{only $only; $default_ty; $($rest)*}
};
(only $only:tt; $default_ty:ty; ($(#[$attribute:meta])*) pub from into $into:ty, $getter:tt, $setter:tt:
    $($exprs:expr),*; $($rest:tt)*) => {
    bitfield_fields!{only $only; @field $(#[$attribute])* (pub) $default_ty, __NO_MASK_FOR_FIELD(u8), $into, $into, $getter, $setter:
                        $($exprs),*}
    bitfield_fields!{only $only; $default_ty; $($rest)*}
};
(only $only:tt; $default_ty:ty; ($(#[$attribute:meta])*) pub into $into:ty, $getter:tt, $setter:tt:
    $($exprs:expr),*; $($rest:tt)*) => {
    bitfield_fields!{only $only; @field $(#[$attribute])* (pub) $default_ty, __NO_MASK_FOR_FIELD(u8), $default_ty, $into, $getter, $setter:
                        $($exprs),*}
    bitfield_fields!{only $only; $default_ty; $($rest)*}
};
(only $only:tt; $default_ty:ty; ($(#[$attribute:meta])*) pub $getter:tt, $setter:tt:  $($exprs:expr),*;
    $($rest:tt)*) => {
    bitfield_fields!{only $only; @field $(#[$attribute])* (pub) $default_ty, __NO_MASK_FOR_FIELD(u8), $default_ty, $default_ty, $getter, $setter:
                            $($exprs),*}
    bitfield_fields!{only $only; $default_ty; $($rest)*}
};

(only $only:tt; $default_ty:ty; ($(#[$attribute:meta])*) $t:ty, mask $mask:ident($mask_t:ty), from into $into:ty, $getter:tt, $setter:tt:
    $($exprs:expr),*; $($rest:tt)*) => {
    bitfield_fields!{only $only; @field $(#[$attribute])* () $t, $mask($mask_t), $into, $into, $getter, $setter: $($exprs),*}
    bitfield_fields!{only $only; $default_ty; $($rest)*}
};

(only $only:tt; $default_ty:ty; ($(#[$attribute:meta])*) $t:ty, mask $mask:ident($mask_t:ty), into $into:ty, $getter:tt, $setter:tt:
    $($exprs:expr),*; $($rest:tt)*) => {
    bitfield_fields!{only $only; @field $(#[$attribute])* () $t, $mask($mask_t), $t, $into, $getter, $setter: $($exprs),*}
    bitfield_fields!{only $only; $default_ty; $($rest)*}
};

(only $only:tt; $default_ty:ty; ($(#[$attribute:meta])*) $t:ty, mask $mask:ident($mask_t:ty), $getter:tt, $setter:tt:  $($exprs:expr),*;
    $($rest:tt)*) => {
    bitfield_fields!{only $only; @field $(#[$attribute])* () $t, $mask($mask_t), $t, $t, $getter, $setter: $($exprs),*}
    bitfield_fields!{only $only; $default_ty; $($rest)*}
};
(only $only:tt; $default_ty:ty; ($(#[$attribute:meta])*) mask $mask:ident($mask_t:ty), from into $into:ty, $getter:tt, $setter:tt:
    $($exprs:expr),*; $($rest:tt)*) => {
    bitfield_fields!{only $only; @field $(#[$attribute])* () $default_ty, $mask($mask_t), $into, $into, $getter, $setter:
                        $($exprs),*}
    bitfield_fields!{only $only; $default_ty; $($rest)*}
};
(only $only:tt; $default_ty:ty; ($(#[$attribute:meta])*) mask $mask:ident($mask_t:ty), into $into:ty, $getter:tt, $setter:tt:
    $($exprs:expr),*; $($rest:tt)*) => {
    bitfield_fields!{only $only; @field $(#[$attribute])* () $default_ty, $mask($mask_t), $default_ty, $into, $getter, $setter:
                        $($exprs),*}
    bitfield_fields!{only $only; $default_ty; $($rest)*}
};
(only $only:tt; $default_ty:ty; ($(#[$attribute:meta])*) mask $mask:ident($mask_t:ty), $getter:tt, $setter:tt:  $($exprs:expr),*;
    $($rest:tt)*) => {
    bitfield_fields!{only $only; @field $(#[$attribute])* () $default_ty, $mask($mask_t), $default_ty, $default_ty, $getter, $setter:
                            $($exprs),*}
    bitfield_fields!{only $only; $default_ty; $($rest)*}
};
(only $only:tt; $default_ty:ty; ($(#[$attribute:meta])*) $t:ty, from into $into:ty, $getter:tt, $setter:tt:
    $($exprs:expr),*; $($rest:tt)*) => {
    bitfield_fields!{only $only; @field $(#[$attribute])* () $t, __NO_MASK_FOR_FIELD(u8), $into, $into, $getter, $setter: $($exprs),*}
    bitfield_fields!{only $only; $default_ty; $($rest)*}
};

(only $only:tt; $default_ty:ty; ($(#[$attribute:meta])*) $t:ty, into $into:ty, $getter:tt, $setter:tt:
    $($exprs:expr),*; $($rest:tt)*) => {
    bitfield_fields!{only $only; @field $(#[$attribute])* () $t, __NO_MASK_FOR_FIELD(u8), $t, $into, $getter, $setter: $($exprs),*}
    bitfield_fields!{only $only; $default_ty; $($rest)*}
};

(only $only:tt; $default_ty:ty; ($(#[$attribute:meta])*) $t:ty, $getter:tt, $setter:tt:  $($exprs:expr),*;
    $($rest:tt)*) => {
    bitfield_fields!{only $only; @field $(#[$attribute])* () $t, __NO_MASK_FOR_FIELD(u8), $t, $t, $getter, $setter: $($exprs),*}
    bitfield_fields!{only $only; $default_ty; $($rest)*}
};
(only $only:tt; $default_ty:ty; ($(#[$attribute:meta])*) from into $into:ty, $getter:tt, $setter:tt:
    $($exprs:expr),*; $($rest:tt)*) => {
    bitfield_fields!{only $only; @field $(#[$attribute])* () $default_ty, __NO_MASK_FOR_FIELD(u8), $into, $into, $getter, $setter:
                        $($exprs),*}
    bitfield_fields!{only $only; $default_ty; $($rest)*}
};
(only $only:tt; $default_ty:ty; ($(#[$attribute:meta])*) into $into:ty, $getter:tt, $setter:tt:
    $($exprs:expr),*; $($rest:tt)*) => {
    bitfield_fields!{only $only; @field $(#[$attribute])* () $default_ty, __NO_MASK_FOR_FIELD(u8), $default_ty, $into, $getter, $setter:
                        $($exprs),*}
    bitfield_fields!{only $only; $default_ty; $($rest)*}
};
(only $only:tt; $default_ty:ty; ($(#[$attribute:meta])*) $getter:tt, $setter:tt:  $($exprs:expr),*;
    $($rest:tt)*) => {
    bitfield_fields!{only $only; @field $(#[$attribute])* () $default_ty, __NO_MASK_FOR_FIELD(u8), $default_ty, $default_ty, $getter, $setter:
                            $($exprs),*}
    bitfield_fields!{only $only; $default_ty; $($rest)*}
};
(only $only:tt; $previous_default_ty:ty; $default_ty:ty; $($rest:tt)*) => {
    bitfield_fields!{only $only; $default_ty; $($rest)*}
};
(only $only:tt; $default_ty:ty; $($rest:tt)*) => {
    bitfield_fields!{only $only; $default_ty; () $($rest)*}
};
(only $only:tt; $($rest:tt)*) => {
    bitfield_fields!{only $only; SET_A_DEFAULT_TYPE_OR_SPECIFY_THE_TYPE_FOR_EACH_FIELDS; $($rest)*}
};
($($rest:tt)*) => {
    bitfield_fields!{only getter; $($rest)*}
    bitfield_fields!{only setter; $($rest)*}
    bitfield_fields!{only mask; $($rest)*}
}
}

/// Generates a `fmt::Debug` implementation.
///
/// This macros must be called from a `impl Debug for ...` block. It will generate the `fmt` method.
///
/// In most of the case, you will not directly call this macros, but use `bitfield`.
///
/// The syntax is `struct TheNameOfTheStruct` followed by the syntax of `bitfield_fields`.
///
/// The write-only fields are ignored.
///
/// # Example
///
/// ```rust
/// # #[macro_use] extern crate bitfield;
/// struct FooBar(u32);
/// bitfield_bitrange!{struct FooBar(u32)}
/// impl FooBar{
///     bitfield_fields!{
///        u32;
///        field1, _: 7, 0;
///        field2, _: 31, 24;
///     }
/// }
///
/// impl std::fmt::Debug for FooBar {
///     bitfield_debug!{
///        struct FooBar;
///        field1, _: 7, 0;
///        field2, _: 31, 24;
///     }
/// }
///
/// fn main() {
///     let foobar = FooBar(0x11223344);
///     println!("{:?}", foobar);

/// }
/// ```
#[macro_export(local_inner_macros)]
macro_rules! bitfield_debug {
(struct $name:ident; $($rest:tt)*) => {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut debug_struct = f.debug_struct(__bitfield_stringify!($name));
        debug_struct.field(".0", &self.0);
        bitfield_debug!{debug_struct, self, $($rest)*}
        debug_struct.finish()
    }
};
($debug_struct:ident, $self:ident, mask $mask:ident($mask_t:ty), $($rest:tt)*) => {
    bitfield_debug!{$debug_struct, $self, $($rest)*}
};
($debug_struct:ident, $self:ident, #[$attribute:meta] $($rest:tt)*) => {
    bitfield_debug!{$debug_struct, $self, $($rest)*}
};
($debug_struct:ident, $self:ident, pub $($rest:tt)*) => {
    bitfield_debug!{$debug_struct, $self, $($rest)*}
};
($debug_struct:ident, $self:ident, _, $setter:tt: $($exprs:expr),*; $($rest:tt)*) => {
    bitfield_debug!{$debug_struct, $self, $($rest)*}
};
($debug_struct:ident, $self:ident, $type:ty; $($rest:tt)*) => {
    bitfield_debug!{$debug_struct, $self, $($rest)*}
};
($debug_struct:ident, $self:ident, $getter:ident, $setter:tt: $msb:expr, $lsb:expr, $count:expr;
    $($rest:tt)*) => {
    let mut array = [$self.$getter(0); $count];
    for (i, e) in (&mut array).into_iter().enumerate() {
        *e = $self.$getter(i);
    }
    $debug_struct.field(__bitfield_stringify!($getter), &array);
    bitfield_debug!{$debug_struct, $self, $($rest)*}
};
($debug_struct:ident, $self:ident, $getter:ident, $setter:tt: $($exprs:expr),*; $($rest:tt)*)
    => {
    $debug_struct.field(__bitfield_stringify!($getter), &$self.$getter());
    bitfield_debug!{$debug_struct, $self, $($rest)*}
};
($debug_struct:ident, $self:ident, from into $into:ty, $($rest:tt)*) => {
    bitfield_debug!{$debug_struct, $self, $($rest)*}
};
($debug_struct:ident, $self:ident, into $into:ty, $($rest:tt)*) => {
    bitfield_debug!{$debug_struct, $self, $($rest)*}
};
($debug_struct:ident, $self:ident, $type:ty, $($rest:tt)*) => {
    bitfield_debug!{$debug_struct, $self, $($rest)*}
};
($debug_struct:ident, $self:ident, ) => {};
}

/// Implements an exhaustive constructor function for a bitfield. Should only be called by `bitfield!` when using `impl new;`
///
/// # Examples
///
/// ```rs
/// bitfield_constructor {0; () -> {}; u8; foo1, set_foo1: 2,0; foo2, set_foo2: 7,2}
/// ```
/// Generates:
/// ```rs
/// pub fn new(set_foo1: u8, set_foo2: u8) -> Self {
///     let mut value = Self(0);
///     value.set_foo1(set_foo1);
///     value.set_foo2(set_foo2);
///     value
/// }
/// ```
#[macro_export(local_inner_macros)]
macro_rules! bitfield_constructor {
(() -> {}; $($rest:tt)*) => {
    bitfield_constructor!{@value; () -> {let mut value = Self(Default::default());}; bool; $($rest)*}
};
(@$value:ident; ($($param:ident: $ty:ty,)*) -> {$($stmt:stmt;)*}; $old_ty:ty; impl $_trait:ident$({$($trait_arg:tt)*})?; $($rest:tt)*) => {
    bitfield_constructor!{@$value; ($($param: $ty,)*) -> {$($stmt;)*}; $old_ty; $($rest)*}
};
(@$value:ident; ($($param:ident: $ty:ty,)*) -> {$($stmt:stmt;)*}; $old_ty:ty; $new_ty:ty; $($rest:tt)*) => {
    bitfield_constructor!{@$value; ($($param: $ty,)*) -> {$($stmt;)*}; $new_ty; $($rest)*}
};
(@$value:ident; ($($param:ident: $ty:ty,)*) -> {$($stmt:stmt;)*}; $default_ty:ty;
$(#[$_:meta])* $(pub)? $(into $_into:ty,)?
$_getter:ident, $setter:ident: $($_expr:expr),*; $($rest:tt)* ) => {
    bitfield_constructor!{@$value;
        ($($param: $ty,)* $setter: $default_ty,) -> {$($stmt;)* $value.$setter($setter);};
        $default_ty; $($rest)*}
};
(@$value:ident; ($($param:ident: $ty:ty,)*) -> {$($stmt:stmt;)*}; $default_ty:ty;
$(#[$_:meta])* $(pub)? $field_type:ty, $(into $_into:ty,)?
$_getter:ident, $setter:ident: $($_expr:expr),*; $($rest:tt)* ) => {
    bitfield_constructor!{@$value;
        ($($param: $ty,)* $setter: $field_type,) -> {$($stmt;)* $value.$setter($setter);};
        $default_ty; $($rest)*}
};
(@$value:ident; ($($param:ident: $ty:ty,)*) -> {$($stmt:stmt;)*}; $_:ty;) => {
    #[allow(clippy::too_many_arguments)]
    pub fn new($($param: $ty),*) -> Self {
        $($stmt;)*
        $value
    }
};
}

/// Implements `BitRange` and `BitRangeMut` for a tuple struct (or "newtype").
///
/// This macro will generate an implementation of the `BitRange` trait for an existing single
/// element tuple struct.
///
/// The syntax is more or less the same as declaring a "newtype", **without** the attributes,
/// documentation comments and pub keyword.
///
/// The difference with a normal "newtype" is the type in parentheses. If the type is `[t]` (where
/// `t` is any of the unsigned integer type), the "newtype" will be generic and implement
/// `BitRange` for `T: AsRef<[t]>` and `BitRangeMut` for `T: AsMut<[t]>` (for example a slice, an array or a `Vec`). You can
/// also use `MSB0 [t]`. The difference will be the positions of the bit. You can use the
/// `bits_positions` example to see where each bits is. If the type is neither of this two, the
/// "newtype" will wrap a value of the specified type and implements `BitRange` the same ways as
/// the wrapped type.
///
/// # Examples
///
/// ```rust
/// # #[macro_use] extern crate bitfield;
/// # fn main() {}
/// struct BitField1(u32);
/// bitfield_bitrange!{struct BitField1(u32)}
///
/// struct BitField2<T>(T);
/// bitfield_bitrange!{struct BitField2([u8])}
///
/// struct BitField3<T>(T);
/// bitfield_bitrange!{struct BitField3(MSB0 [u8])}
/// ```
///
#[macro_export(local_inner_macros)]
macro_rules! bitfield_bitrange {
(@impl_bitrange_slice $name:ident, $slice_ty:ty, $bitrange_ty:ty) => {
    impl<T: AsRef<[$slice_ty]>> crate::utils::bitfield::BitRange<$bitrange_ty>
        for $name<T> {
            fn bit_range(&self, msb: usize, lsb: usize) -> $bitrange_ty {
                let bit_len = crate::utils::bitfield::size_of::<$slice_ty>()*8;
                let value_bit_len = crate::utils::bitfield::size_of::<$bitrange_ty>()*8;
                let mut value = 0;
                for i in (lsb..=msb).rev() {
                    value <<= 1;
                    value |= ((self.0.as_ref()[i/bit_len] >> (i%bit_len)) & 1) as $bitrange_ty;
                }
                value << (value_bit_len - (msb - lsb + 1)) >> (value_bit_len - (msb - lsb + 1))
            }
    }
    impl<T: AsMut<[$slice_ty]>> crate::utils::bitfield::BitRangeMut<$bitrange_ty>
        for $name<T> {

            fn set_bit_range(&mut self, msb: usize, lsb: usize, value: $bitrange_ty) {
                let bit_len = crate::utils::bitfield::size_of::<$slice_ty>()*8;
                let mut value = value;
                for i in lsb..=msb {
                    self.0.as_mut()[i/bit_len] &= !(1 << (i%bit_len));
                    self.0.as_mut()[i/bit_len] |= (value & 1) as $slice_ty << (i%bit_len);
                    value >>= 1;
                }
            }
        }
};
(@impl_bitrange_slice_msb0 $name:ident, $slice_ty:ty, $bitrange_ty:ty) => {
    impl<T: AsRef<[$slice_ty]>> crate::utils::bitfield::BitRange<$bitrange_ty>
        for $name<T> {
        fn bit_range(&self, msb: usize, lsb: usize) -> $bitrange_ty {
            let bit_len = crate::utils::bitfield::size_of::<$slice_ty>()*8;
            let value_bit_len = crate::utils::bitfield::size_of::<$bitrange_ty>()*8;
            let mut value = 0;
            for i in lsb..=msb {
                value <<= 1;
                value |= ((self.0.as_ref()[i/bit_len] >> (bit_len - i%bit_len - 1)) & 1)
                    as $bitrange_ty;
            }
            value << (value_bit_len - (msb - lsb + 1)) >> (value_bit_len - (msb - lsb + 1))
        }
    }
    impl<T: AsMut<[$slice_ty]>> crate::utils::bitfield::BitRangeMut<$bitrange_ty>
        for $name<T> {
        fn set_bit_range(&mut self, msb: usize, lsb: usize, value: $bitrange_ty) {
            let bit_len = crate::utils::bitfield::size_of::<$slice_ty>()*8;
            let mut value = value;
            for i in (lsb..=msb).rev() {
                self.0.as_mut()[i/bit_len] &= !(1 << (bit_len - i%bit_len - 1));
                self.0.as_mut()[i/bit_len] |= (value & 1) as $slice_ty
                    << (bit_len - i%bit_len - 1);
                value >>= 1;
            }
        }
    }
};
(struct $name:ident([$t:ty])) => {
    bitfield_bitrange!(@impl_bitrange_slice $name, $t, u8);
    bitfield_bitrange!(@impl_bitrange_slice $name, $t, u16);
    bitfield_bitrange!(@impl_bitrange_slice $name, $t, u32);
    bitfield_bitrange!(@impl_bitrange_slice $name, $t, u64);
    bitfield_bitrange!(@impl_bitrange_slice $name, $t, u128);
    bitfield_bitrange!(@impl_bitrange_slice $name, $t, i8);
    bitfield_bitrange!(@impl_bitrange_slice $name, $t, i16);
    bitfield_bitrange!(@impl_bitrange_slice $name, $t, i32);
    bitfield_bitrange!(@impl_bitrange_slice $name, $t, i64);
    bitfield_bitrange!(@impl_bitrange_slice $name, $t, i128);
};
(struct $name:ident(MSB0 [$t:ty])) => {
    bitfield_bitrange!(@impl_bitrange_slice_msb0 $name, $t, u8);
    bitfield_bitrange!(@impl_bitrange_slice_msb0 $name, $t, u16);
    bitfield_bitrange!(@impl_bitrange_slice_msb0 $name, $t, u32);
    bitfield_bitrange!(@impl_bitrange_slice_msb0 $name, $t, u64);
    bitfield_bitrange!(@impl_bitrange_slice_msb0 $name, $t, u128);
    bitfield_bitrange!(@impl_bitrange_slice_msb0 $name, $t, i8);
    bitfield_bitrange!(@impl_bitrange_slice_msb0 $name, $t, i16);
    bitfield_bitrange!(@impl_bitrange_slice_msb0 $name, $t, i32);
    bitfield_bitrange!(@impl_bitrange_slice_msb0 $name, $t, i64);
    bitfield_bitrange!(@impl_bitrange_slice_msb0 $name, $t, i128);
};
(struct $name:ident($t:ty)) => {
    impl<T> crate::utils::bitfield::BitRange<T> for $name where $t: crate::utils::bitfield::BitRange<T> {
        fn bit_range(&self, msb: usize, lsb: usize) -> T {
            self.0.bit_range(msb, lsb)
        }
    }
    impl<T> crate::utils::bitfield::BitRangeMut<T> for $name where $t: crate::utils::bitfield::BitRangeMut<T> {
        fn set_bit_range(&mut self, msb: usize, lsb: usize, value: T) {
            self.0.set_bit_range(msb, lsb, value);
        }
    }
};
}

/// Combines `bitfield_bitrange` and `bitfield_fields`.
///
/// The syntax of this macro is the syntax of a tuple struct, including attributes and
/// documentation comments, followed by a semicolon, some optional elements, and finally the fields
/// as described in the `bitfield_fields` documentation.
///
/// The first optional element is `no default BitRange;`. With that, no implementation of
/// `BitRange` will be generated.
///
/// The second optional element is a set of lines of the form `impl <Trait>;`. The following traits are supported:
/// * `Debug`; This will generate an implementation of `fmt::Debug` with the `bitfield_debug` macro.
/// * `BitAnd`, `BitOr`, `BitXor`; These will generate implementations of the relevant `ops::Bit___` and `ops::Bit___Assign` traits.
/// * `new`; This will generate a constructor that calls all of the bitfield's setter methods with an argument of the appropriate type
/// * `new{constructor_name(setter_name: setter_type, ...)}`; This will generate a constructor that calls a given subset of the bitfield's setter methods
///
/// The difference with calling those macros separately is that `bitfield_fields` is called
/// from an appropriate `impl` block. If you use the non-slice form of `bitfield_bitrange`, the
/// default type for `bitfield_fields` will be set to the wrapped fields.
///
/// See the documentation of these macros for more information on their respective syntax.
///
/// # Example
///
/// ```rust
/// # #[macro_use] extern crate bitfield;
/// # fn main() {}
/// bitfield!{
///   pub struct BitField1(u16);
///   impl Debug;
///   // The fields default to u16
///   field1, set_field1: 10, 0;
///   pub field2, _ : 12, 3;
/// }
/// ```
///
/// or with a custom `BitRange` and `BitRangeMut` implementation :
/// ```rust
/// # #[macro_use] extern crate bitfield;
/// # use crate::utils::bitfield::{BitRange, BitRangeMut};
/// # fn main() {}
/// bitfield!{
///   pub struct BitField1(u16);
///   no default BitRange;
///   impl Debug;
///   impl BitAnd;
///   u8;
///   field1, set_field1: 10, 0;
///   pub field2, _ : 12, 3;
/// }
/// impl BitRange<u8> for BitField1 {
///     fn bit_range(&self, msb: usize, lsb: usize) -> u8 {
///         let width = msb - lsb + 1;
///         let mask = (1 << width) - 1;
///         ((self.0 >> lsb) & mask) as u8
///     }
/// }
/// impl BitRangeMut<u8> for BitField1 {
///     fn set_bit_range(&mut self, msb: usize, lsb: usize, value: u8) {
///         self.0 = (value as u16) << lsb;
///     }
/// }
/// ```
#[macro_export(local_inner_macros)]
macro_rules! bitfield {
// Force `impl <Trait>` to always be after `no default BitRange` it the two are present.
// This simplify the rest of the macro.
($(#[$attribute:meta])* $vis:vis struct $name:ident($($type:tt)*); $(impl $trait:ident$({$($trait_arg:tt)*})?;)+ no default BitRange; $($rest:tt)*) => {
        bitfield!{$(#[$attribute])* $vis struct $name($($type)*); no default BitRange; $(impl $trait$({$($trait_arg)*})?;)* $($rest)*}
    };

// If we have `impl <Trait>` without `no default BitRange`, we will still match, because when
// we call `bitfield_bitrange`, we add `no default BitRange`.
($(#[$attribute:meta])* $vis:vis struct $name:ident([$t:ty]); no default BitRange; impl $trait:ident$({$($trait_arg:tt)*})?; $($rest:tt)*) => {
    bitfield_impl!{$trait$({$($trait_arg)*})? for struct $name([$t]); $($rest)*}

    bitfield!{$(#[$attribute])* $vis struct $name([$t]); no default BitRange;  $($rest)*}
};
($(#[$attribute:meta])* $vis:vis struct $name:ident([$t:ty]); no default BitRange; $($rest:tt)*) => {
    $(#[$attribute])*
    $vis struct $name<T>(pub T);

    //impl<T: AsMut<[$t]> + AsRef<[$t]>> $name<T> {
    //    bitfield_fields!{$($rest)*}
    //}
    impl<T: AsRef<[$t]>> $name<T> {
        bitfield_fields!{only getter; $($rest)*}
    }
    impl<T: AsMut<[$t]>> $name<T> {
        bitfield_fields!{only setter; $($rest)*}
    }
};
($(#[$attribute:meta])* $vis:vis struct $name:ident([$t:ty]); $($rest:tt)*) => {
    bitfield_bitrange!(struct $name([$t]));
    bitfield!{$(#[$attribute])* $vis struct $name([$t]); no default BitRange; $($rest)*}
};

// The only difference between the MSB0 version anf the non-MSB0 version, is the BitRange
// implementation. We delegate everything else to the non-MSB0 version of the macro.
($(#[$attribute:meta])* $vis:vis struct $name:ident(MSB0 [$t:ty]); no default BitRange; $($rest:tt)*) => {
    bitfield!{$(#[$attribute])* $vis struct $name([$t]); no default BitRange; $($rest)*}
};
($(#[$attribute:meta])* $vis:vis struct $name:ident(MSB0 [$t:ty]); $($rest:tt)*) => {
    bitfield_bitrange!(struct $name(MSB0 [$t]));
    bitfield!{$(#[$attribute])* $vis struct $name([$t]); no default BitRange; $($rest)*}
};

($(#[$attribute:meta])* $vis:vis struct $name:ident($t:ty); no default BitRange; impl $trait:ident$({$($trait_arg:tt)*})?; $($rest:tt)*) => {
    bitfield_impl!{$trait$({$($trait_arg)*})? for struct $name($t); $($rest)*}

    bitfield!{$(#[$attribute])* $vis struct $name($t); no default BitRange; $($rest)*}
};
($(#[$attribute:meta])* $vis:vis struct $name:ident($t:ty); no default BitRange; $($rest:tt)*) => {
    $(#[$attribute])*
    $vis struct $name(pub $t);

    impl $name {
        bitfield_fields!{$t; $($rest)*}
        }
};
($(#[$attribute:meta])* $vis:vis struct $name:ident($t:ty); $($rest:tt)*) => {
    bitfield_bitrange!(struct $name($t));
    bitfield!{$(#[$attribute])* $vis struct $name($t); no default BitRange; $($rest)*}
};
}

/// A trait to get ranges of bits.
pub(crate) trait BitRange<T> {
    /// Get a range of bits.
    fn bit_range(&self, msb: usize, lsb: usize) -> T;
}

/// A trait to set ranges of bits.
pub(crate) trait BitRangeMut<T> {
    /// Set a range of bits.
    fn set_bit_range(&mut self, msb: usize, lsb: usize, value: T);
}

/// A trait to get a single bit.
///
/// This trait is implemented for all type that implement `BitRange<u8>`.
pub(crate) trait Bit {
    /// Get a single bit.
    fn bit(&self, bit: usize) -> bool;
}

/// A trait to set a single bit.
///
/// This trait is implemented for all type that implement `BitRangeMut<u8>`.
pub(crate) trait BitMut {
    /// Set a single bit.
    fn set_bit(&mut self, bit: usize, value: bool);
}

impl<T: BitRange<u8>> Bit for T {
    fn bit(&self, bit: usize) -> bool {
        self.bit_range(bit, bit) != 0
    }
}

impl<T: BitRangeMut<u8>> BitMut for T {
    fn set_bit(&mut self, bit: usize, value: bool) {
        self.set_bit_range(bit, bit, value as u8);
    }
}

macro_rules! impl_bitrange_for_u {
($t:ty, $bitrange_ty:ty) => {
    impl BitRange<$bitrange_ty> for $t {
        #[inline]
        #[allow(clippy::cast_lossless)]
        #[allow(clippy::manual_bits)]
        fn bit_range(&self, msb: usize, lsb: usize) -> $bitrange_ty {
            let bit_len = size_of::<$t>()*8;
            let result_bit_len = size_of::<$bitrange_ty>()*8;
            let result = ((*self << (bit_len - msb - 1)) >> (bit_len - msb - 1 + lsb))
                as $bitrange_ty;
            result << (result_bit_len - (msb - lsb + 1)) >> (result_bit_len - (msb - lsb + 1))
        }
    }

    impl BitRangeMut<$bitrange_ty> for $t {
        #[inline]
        #[allow(clippy::cast_lossless)]
        #[allow(clippy::manual_bits)]
        fn set_bit_range(&mut self, msb: usize, lsb: usize, value: $bitrange_ty) {
            let bit_len = size_of::<$t>()*8;
            let mask: $t = !(0 as $t)
                << (bit_len - msb - 1)
                >> (bit_len - msb - 1 + lsb)
                << (lsb);
            *self &= !mask;
            *self |= (value as $t << lsb) & mask;
        }
    }
}
}

macro_rules! impl_bitrange_for_u_combinations {
((),($($bitrange_ty:ty),*)) => {

};
(($t:ty),($($bitrange_ty:ty),*)) => {
    $(impl_bitrange_for_u!{$t, $bitrange_ty})*
};
(($t_head:ty, $($t_rest:ty),*),($($bitrange_ty:ty),*)) => {
    impl_bitrange_for_u_combinations!{($t_head), ($($bitrange_ty),*)}
    impl_bitrange_for_u_combinations!{($($t_rest),*), ($($bitrange_ty),*)}
};
}

impl_bitrange_for_u_combinations! {(u8, u16, u32, u64, u128), (u8, u16, u32, u64, u128)}
impl_bitrange_for_u_combinations! {(u8, u16, u32, u64, u128), (i8, i16, i32, i64, i128)}

// Same as std::stringify but callable from local_inner_macros macros defined inside
// this crate.
#[macro_export]
#[doc(hidden)]
macro_rules! __bitfield_stringify {
    ($s:ident) => {
        stringify!($s)
    };
}

// Same as std::debug_assert but callable from local_inner_macros macros defined inside
// this crate.
#[macro_export]
#[doc(hidden)]
macro_rules! __bitfield_debug_assert {
    ($e:expr) => {
        debug_assert!($e)
    };
}
