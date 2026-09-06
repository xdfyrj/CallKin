#[inline(never)]
fn largest<T: PartialOrd>(list: &[T]) -> &T {
    let mut largest = &list[0];

    for item in list {
        if item > largest {
            largest = item;
        }
    }

    largest
}

fn main() {
    let char_list: [u8; 5] = [34, 50, 25, 100, 65];

    let result = largest(&char_list);
    println!("The largest number is {result}");

    let number_list: [i32; 8] = [102, 34, 6000, 89, 54, 2, 43, 8];

    let result = largest(&number_list);
    println!("The largest number is {result}");
}