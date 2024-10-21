function Parse-IniFile ($file) {
    $ini = @{}
    $section = "Config"
    $ini[$section] = @{}

    switch -regex -file $file {
        #Comments.
        "^\s*([#;].*)$" {
            continue
        }     
        #Section.
        "^\[(.+)\]\s*$" {
            $section = $matches[1].Trim()
            $ini[$section] = @{}
            continue
        }
        #Decimal.
        "^\s*(.+?)\s*=\s*(\d+[.,]\d+)(?>\s*(?>[;#].*)|\s*$)$" {
            $name, $value = $matches[1..2]
            "dec. $($section)*$($name)*$($value)*"
            $ini[$section][$name] = [decimal]$value.replace(',','.')
            continue
        }
        #Int.
        "^\s*(.+?)\s*=\s*(\d+)(?>\s*(?>[;#].*)|\s*$)$" {
            $name, $value = $matches[1..2]
            "int. $($section)*$($name)*$($value)*"
            $ini[$section][$name] = [int]$value
            continue
        }
        #Everything else.
        "^\s*(.+)\s*=\s*(.*)" {
            "other : $_"
            $name, $value = $matches[1..2]
            "else. $($section)*$($name)*$($value)*"
            $ini[$section][$name] = $value.Trim()
        }
    }
    $ini
}