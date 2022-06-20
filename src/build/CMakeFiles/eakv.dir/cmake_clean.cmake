file(REMOVE_RECURSE
  "e_akv.pdb"
  "e_akv.so"
)

# Per-language clean rules from dependency scanning.
foreach(lang C)
  include(CMakeFiles/eakv.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
