use serde::Deserialize;

use crate::client::Client;
use crate::error::Error;

/// One page of a cursor-paginated collection.
///
/// The API always returns this shape, whatever the element type.
#[derive(Debug, Clone, Deserialize)]
pub struct Page<T> {
    #[serde(default = "Vec::new")]
    pub data: Vec<T>,
    #[serde(default)]
    pub has_more: bool,
    /// Opaque; feed it back as `starting_after`.
    #[serde(default)]
    pub next_cursor: Option<String>,
    /// Only populated when the caller asks for it, since counting is expensive
    /// on the provider's side.
    #[serde(default)]
    pub total_count: Option<u64>,
}

impl<T> Page<T> {
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Convert element types while preserving cursor state, e.g. to map raw
    /// wire structs onto domain types before they leave the SDK.
    pub fn map<U, F>(self, f: F) -> Page<U>
    where
        F: FnMut(T) -> U,
    {
        Page {
            data: self.data.into_iter().map(f).collect(),
            has_more: self.has_more,
            next_cursor: self.next_cursor,
            total_count: self.total_count,
        }
    }
}

/// Query knobs shared by every list endpoint.
#[derive(Debug, Clone, Default)]
pub struct ListParams {
    pub limit: Option<u32>,
    pub starting_after: Option<String>,
    pub created_gte: Option<i64>,
    pub created_lt: Option<i64>,
    pub extra: Vec<(String, String)>,
}

impl ListParams {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn limit(mut self, limit: u32) -> Self {
        self.limit = Some(limit.clamp(1, 100));
        self
    }

    pub fn created_between(mut self, from: i64, until: i64) -> Self {
        self.created_gte = Some(from);
        self.created_lt = Some(until);
        self
    }

    pub fn filter(mut self, key: &str, value: impl Into<String>) -> Self {
        self.extra.push((key.to_string(), value.into()));
        self
    }

    pub(crate) fn to_query(&self) -> Vec<(String, String)> {
        let mut query = Vec::with_capacity(4 + self.extra.len());
        if let Some(limit) = self.limit {
            query.push(("limit".to_string(), limit.to_string()));
        }
        if let Some(cursor) = &self.starting_after {
            query.push(("starting_after".to_string(), cursor.clone()));
        }
        if let Some(from) = self.created_gte {
            query.push(("created[gte]".to_string(), from.to_string()));
        }
        if let Some(until) = self.created_lt {
            query.push(("created[lt]".to_string(), until.to_string()));
        }
        query.extend(self.extra.iter().cloned());
        query
    }
}

/// Walks a collection page by page, yielding one element at a time.
///
/// Fetches lazily: nothing is requested until the first `next()`, and a caller
/// that breaks early stops paying for pages it never reads.
pub struct Paginator<'a, T> {
    client: &'a Client,
    path: String,
    params: ListParams,
    buffer: std::vec::IntoIter<T>,
    exhausted: bool,
    pages_fetched: usize,
}

impl<'a, T> Paginator<'a, T> {
    pub(crate) fn new(client: &'a Client, path: impl Into<String>, params: ListParams) -> Self {
        Paginator {
            client,
            path: path.into(),
            params,
            buffer: Vec::new().into_iter(),
            exhausted: false,
            pages_fetched: 0,
        }
    }

    pub fn pages_fetched(&self) -> usize {
        self.pages_fetched
    }
}

impl<'a, T> Iterator for Paginator<'a, T>
where
    T: serde::de::DeserializeOwned + Cursored,
{
    type Item = Result<T, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(item) = self.buffer.next() {
                return Some(Ok(item));
            }
            if self.exhausted {
                return None;
            }

            let page: Page<T> = match self.client.list_page(&self.path, &self.params) {
                Ok(page) => page,
                Err(e) => {
                    self.exhausted = true;
                    return Some(Err(e));
                }
            };
            self.pages_fetched += 1;

            // Prefer the server's cursor; fall back to the last id, which is
            // what the older API version expects.
            let next_cursor = page
                .next_cursor
                .clone()
                .or_else(|| page.data.last().map(|item| item.cursor().to_string()));

            self.exhausted = !page.has_more || next_cursor.is_none() || page.data.is_empty();
            self.params.starting_after = next_cursor;
            self.buffer = page.data.into_iter();

            if self.exhausted && self.buffer.len() == 0 {
                return None;
            }
        }
    }
}

/// Implemented by every listable resource so the paginator can derive a cursor
/// when the server omits one.
pub trait Cursored {
    fn cursor(&self) -> &str;
}
