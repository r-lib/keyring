# Invalid encoding (not in iconvlist) returns error

    Code
      get_encoding_opt()
    Condition
      Error in `get_encoding_opt()`:
      ! Encoding not found in iconvlist(). Did you mean macintosh?

# iconv suggestion works as expected

    Code
      get_encoding_opt()
    Condition
      Error in `get_encoding_opt()`:
      ! Encoding not found in iconvlist(). Did you mean UTF-16LE?

