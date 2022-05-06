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
rule base64_stratum
{

  meta:
    description = "base64 encode stratum protocol"
    date = "2022/5/6"
  
  strings:
    $1 = "c3RyYXR1bSt0Y3A6Ly"
    $2 = "N0cmF0dW0rdGNwOi8v"
    $3 = "zdHJhdHVtK3RjcDovL"
    $4 = "c3RyYXR1bSt1ZHA6Ly"
    $5 = "N0cmF0dW0rdWRwOi8v"
    $6 = "zdHJhdHVtK3VkcDovL"

  condition:
    any of ($*)
}
