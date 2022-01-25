rule stratum
{
  meta:
    description = "stratum mining protocol"
    author = "ivoripuion"
    date = "2022/1/25"
  
  strings:
    $s1 = "mining.subcribe"
    $s2 = "mining.notify"
    $s3 = "mining.authorize"
    $s4 = "mining.submit"
    $s5 = "mining.set_difficulty"
  
  condition:
    any of ($s*)
}
