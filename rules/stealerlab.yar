/*
    STEALERLAB - Reglas YARA
    TFM - Analisis dinamico de stealers en Windows
    Autor: Jose Arturo Beltre Castro

    Taxonomia en tres niveles:
      Nivel 1 (sample):     hash/cadenas singulares - detecta la muestra exacta
      Nivel 2 (family):     rasgos estructurales de la familia (mas estables)
      Nivel 3 (behavioral): comportamiento generico de stealer

    Prototipos validados sintacticamente (yara compila sin errores).
    No se ha medido la tasa de falsos positivos en produccion (ver seccion 8.3 del TFM).
*/
import "pe"
import "hash"

/* ===== NIVEL 1 - SAMPLE-SPECIFIC ===== */
rule STEALERLAB_LummaC2_sample_L1 {
    meta:
        description = "LummaC2 - muestra exacta analizada (nivel 1)"
        level = "1-sample"
        sha256 = "727c152c2f20469adf1743fb4e5de698615b806c0cce4322fa68112a1b74b1b1"
    condition:
        hash.sha256(0, filesize) == "727c152c2f20469adf1743fb4e5de698615b806c0cce4322fa68112a1b74b1b1"
}
rule STEALERLAB_Vidar_sample_L1 {
    meta:
        description = "Vidar - muestra exacta analizada (nivel 1)"
        level = "1-sample"
        sha256 = "082370aaf679a20e722fec6c88ab73803063e34683b0106e11b0d1999508cec4"
    condition:
        hash.sha256(0, filesize) == "082370aaf679a20e722fec6c88ab73803063e34683b0106e11b0d1999508cec4"
}
rule STEALERLAB_StealC_sample_L1 {
    meta:
        description = "StealC - muestra exacta analizada (nivel 1)"
        level = "1-sample"
        sha256 = "41aa2a9f47277b32efbb369b5b92c79d444d3c524cd55142d9e85603ddea3478"
    condition:
        hash.sha256(0, filesize) == "41aa2a9f47277b32efbb369b5b92c79d444d3c524cd55142d9e85603ddea3478"
}
rule STEALERLAB_RedLine_sample_L1 {
    meta:
        description = "RedLine - muestra exacta analizada (nivel 1)"
        level = "1-sample"
        sha256 = "d05986e4e8a5d6818ae373894b7af0e78fddd99c57d1b3b76357dfcafefc0cbb"
    condition:
        hash.sha256(0, filesize) == "d05986e4e8a5d6818ae373894b7af0e78fddd99c57d1b3b76357dfcafefc0cbb"
}
rule STEALERLAB_Mystic_sample_L1 {
    meta:
        description = "Mystic - muestra exacta analizada (nivel 1)"
        level = "1-sample"
        sha256 = "47439044a81b96be0bb34e544da881a393a30f0272616f52f54405b4bf288c7c"
    condition:
        hash.sha256(0, filesize) == "47439044a81b96be0bb34e544da881a393a30f0272616f52f54405b4bf288c7c"
}
rule STEALERLAB_Raccoon_sample_L1 {
    meta:
        description = "Raccoon - muestra exacta analizada (nivel 1)"
        level = "1-sample"
        sha256 = "2ef11e6ae721f24e08cdd1094f07a4d3ac8c57534217e387c6272a2a5a6fa3f7"
    condition:
        hash.sha256(0, filesize) == "2ef11e6ae721f24e08cdd1094f07a4d3ac8c57534217e387c6272a2a5a6fa3f7"
}

/* ===== NIVEL 2 - FAMILY-SPECIFIC ===== */
rule STEALERLAB_RedLine_fakemeta_L2 {
    meta:
        description = "RedLine - metadatos PE falsificados (nivel 2, heuristica; derivada de una muestra)"
        level = "2-family"
    condition:
        pe.is_pe and
        (pe.version_info["ProductName"] == "CoralReefApp" or
         pe.version_info["OriginalFilename"] == "Ctgy.exe" or
         pe.version_info["CompanyName"] == "Jumper Team")
}
rule STEALERLAB_Raccoon_imphash_L2 {
    meta:
        description = "Raccoon - imphash observado (nivel 2; el imphash puede compartirse entre familias, correlacionar)"
        level = "2-family"
        imphash = "E9FA0DC321486A0834A2759B64589900"
    condition:
        pe.is_pe and pe.imphash() == "e9fa0dc321486a0834a2759b64589900"
}

/* ===== NIVEL 3 - BEHAVIORAL / GENERIC ===== */
rule STEALERLAB_generic_stealer_strings_L3 {
    meta:
        description = "Comportamiento generico stealer - rutas de datos sensibles (nivel 3, cobertura amplia)"
        level = "3-behavioral"
        nota = "Requiere >=3 coincidencias + PE. Mayor propension a falsos positivos."
    strings:
        $b1 = "\\Login Data" ascii wide
        $b2 = "\\Cookies" ascii wide
        $b3 = "\\Web Data" ascii wide
        $b4 = "wallet.dat" ascii wide
        $b5 = "\\Local State" ascii wide
        $b6 = "cryptocurrency" ascii wide nocase
    condition:
        pe.is_pe and 3 of ($b*)
}
