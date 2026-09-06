#[inline(never)]
fn largest_u8(list: &[u8]) -> &u8 {
    let mut largest = &list[0];

    for item in list {
        if item > largest {
            largest = item;
        }
    }

    largest
}

#[inline(never)]
fn largest_i32(list: &[i32]) -> &i32 {
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

    let result = largest_u8(&char_list);
    println!("The largest number is {result}");

    let number_list: [i32; 8] = [102, 34, 6000, 89, 54, 2, 43, 8];

    let result = largest_i32(&number_list);
    println!("The largest number is {result}");
}