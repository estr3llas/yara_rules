import "pe"

rule pe_no_import_table {
    meta:
        author = "estrellas"
        description = "A rule to detect .exes who doesnt have any imports"
        date = "2023-10-05"

    condition:
        pe.is_pe
        and pe.number_of_imports == 0
} 
