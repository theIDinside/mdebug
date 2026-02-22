# MDB Usage Guide

## Index

- [Resolvers](#resolvers) - Displaying variables in a user friendly way

## Resolvers

Resolvers are custom functions that transform complex data structures into a list of members to display to the user. When debugging, native data structures like `std::vector`, `std::string`, or custom container types often expose internal implementation details that make it difficult to inspect their actual contents. Resolvers allow you to define how these types should be displayed and accessed, showing the meaningful data rather than raw pointers and internal bookkeeping.

### Registering a Resolver

Resolvers are registered using the global `registerResolver` function, which takes two arguments:

**Configuration Object:**

```typescript
{
  name: string,          // Human-readable name for the resolver
  match: string,         // Regex pattern to match type names
  objectFileName: string // Filter by object file (use '*' for all files)
}
```

**Resolver Function:**

```typescript
function(variable, offset, count): variable[]
```

- `variable`: The variable to resolve
- `offset`: Starting index for array-like types (used for pagination)
- `count`: Number of elements to return (used for pagination)
- **Returns**: Array of resolved variables

The `offset` and `count` parameters enable efficient pagination for large containers, allowing UI clients to load data incrementally rather than all at once.

### Example: std::vector Resolver

Here's a complete example that resolves `std::vector` from libstdc++:

```javascript
registerResolver(
  { name: 'std::vector', match: 'vector<.*?>', objectFileName: '*' },
  function (variable, offset, count) {
    // Get the internal implementation members
    const impl = variable.member('_M_impl')
    if (!impl) {
      return []
    }

    // Get the start and finish pointers
    const startPtr = impl.member('_M_start')
    const finishPtr = impl.member('_M_finish')

    if (!startPtr || !finishPtr) {
      return []
    }
    // pointers when used like a primitive works on byte-boundaries
    // not on type-size boundaries. This may or may not change in the future.
    const diff = finishPtr - startPtr
    const elemSize = BigInt(startPtr.type().pointeeSize())
    const totalSize = Number(diff / elemSize)
    return startPtr.asArray(totalSize)
  }
)
```

This resolver:

1. Matches any type matching the pattern `vector<.*?>`
2. Navigates the internal `_Vector_impl` structure
3. Calculates the number of elements by comparing start and finish pointers
4. Returns the elements as an array for display
