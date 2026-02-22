registerResolver(
  { name: 'std::vector', match: 'vector<.*?>', objectFileName: '*' },
  function (variable, offset, count) {
    // std::vector in libstdc++ has basically the structure:
    // struct _Vector_impl {
    //   T* _M_start;        // pointer to beginning of allocated storage
    //   T* _M_finish;       // pointer to one past last element
    //   T* _M_end_of_storage; // pointer to end of allocated storage
    // }

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
    const diff = finishPtr - startPtr
    const elemSize = BigInt(startPtr.type().pointeeSize())
    const totalSize = Number(diff / elemSize)
    return startPtr.asArray(totalSize)
  }
)
