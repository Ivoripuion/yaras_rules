rule cpuminer
{
  meta:
    description = "https://github.com/pooler/cpuminer"
    author = "ivoripuion"
    date = "2022/01/02"
  
  strings:
    $s1 = "submit_upstream_work"
  
  condition:
    any of ($s*) and uint32(0) == 0x464C457F
}
