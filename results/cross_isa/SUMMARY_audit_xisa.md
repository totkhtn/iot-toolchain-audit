# Cross-ISA function localization (held-out ISA as test set; GT v2; mean ± std over 10 seeds)

## ARM

| Setting | n GT files/seed | Share payload / helper / library | AUC | AP | Hit@5 | AP function size | AP random |
|---|---|---|---|---|---|---|---|
| unfiltered, all functions | 824 | 0.590±0.168 / 0.000±0.001 / 0.410±0.169 | 0.511±0.014 | 0.450±0.059 | 0.796±0.075 | 0.337±0.000 | 0.146±0.000 |
| unfiltered, library removed | 824 | 0.854±0.033 / 0.032±0.016 / 0.114±0.038 | 0.547±0.017 | 0.715±0.033 | 0.998±0.002 | 0.735±0.000 | 0.551±0.000 |
| library-aware, library removed | 824 | 0.928±0.029 / 0.022±0.013 / 0.050±0.026 | 0.570±0.030 | 0.748±0.035 | 1.000±0.001 | 0.735±0.000 | 0.551±0.000 |

library-aware − unfiltered (same set of non-library functions), n = 10 pairs:
- Δ payload = +0.074 (p = 0.00586)
- Δ other = -0.064 (p = 0.0137)
- Δ ap = +0.033 (p = 0.0195)
- Δ auc = +0.023 (p = 0.105)
- Δ hit5 = +0.002 (p = 0.00781)
- AP library-aware − AP function size = +0.012 (p = 0.275)
- AP library-aware − AP random = +0.197 (p = 0.00195)

## MIPS

| Setting | n GT files/seed | Share payload / helper / library | AUC | AP | Hit@5 | AP function size | AP random |
|---|---|---|---|---|---|---|---|
| unfiltered, all functions | 72 | 0.090±0.023 / 0.000±0.000 / 0.910±0.023 | 0.518±0.031 | 0.402±0.014 | 0.426±0.177 | 0.615±0.000 | 0.228±0.000 |
| unfiltered, library removed | 72 | 0.642±0.083 / 0.090±0.021 / 0.268±0.078 | 0.459±0.026 | 0.682±0.025 | 0.989±0.011 | 0.842±0.000 | 0.648±0.000 |
| library-aware, library removed | 72 | 0.725±0.047 / 0.080±0.020 / 0.195±0.044 | 0.452±0.028 | 0.701±0.029 | 1.000±0.000 | 0.842±0.000 | 0.648±0.000 |

library-aware − unfiltered (same set of non-library functions), n = 10 pairs:
- Δ payload = +0.084 (p = 0.0137)
- Δ other = -0.073 (p = 0.0195)
- Δ ap = +0.019 (p = 0.16)
- Δ auc = -0.007 (p = 0.625)
- Δ hit5 = +0.011 (p = 0.0312)
- AP library-aware − AP function size = -0.140 (p = 0.00195)
- AP library-aware − AP random = +0.053 (p = 0.00195)

## PowerPC

| Setting | n GT files/seed | Share payload / helper / library | AUC | AP | Hit@5 | AP function size | AP random |
|---|---|---|---|---|---|---|---|
| unfiltered, all functions | 55 | 0.024±0.022 / 0.002±0.004 / 0.974±0.023 | 0.502±0.024 | 0.428±0.009 | 0.173±0.047 | 0.531±0.000 | 0.214±0.000 |
| unfiltered, library removed | 55 | 0.359±0.143 / 0.268±0.198 / 0.373±0.140 | 0.453±0.043 | 0.634±0.019 | 0.958±0.056 | 0.763±0.000 | 0.618±0.000 |
| library-aware, library removed | 55 | 0.378±0.099 / 0.464±0.146 / 0.157±0.079 | 0.484±0.051 | 0.628±0.023 | 0.996±0.008 | 0.763±0.000 | 0.618±0.000 |

library-aware − unfiltered (same set of non-library functions), n = 10 pairs:
- Δ payload = +0.020 (p = 0.922)
- Δ other = -0.216 (p = 0.00586)
- Δ ap = -0.006 (p = 0.492)
- Δ auc = +0.032 (p = 0.16)
- Δ hit5 = +0.038 (p = 0.0156)
- AP library-aware − AP function size = -0.135 (p = 0.00195)
- AP library-aware − AP random = +0.010 (p = 0.275)

## x64

| Setting | n GT files/seed | Share payload / helper / library | AUC | AP | Hit@5 | AP function size | AP random |
|---|---|---|---|---|---|---|---|
| unfiltered, all functions | 68 | 0.359±0.150 / 0.004±0.008 / 0.638±0.151 | 0.566±0.011 | 0.597±0.016 | 0.593±0.333 | 0.545±0.000 | 0.344±0.000 |
| unfiltered, library removed | 68 | 0.750±0.151 / 0.104±0.121 / 0.146±0.088 | 0.569±0.014 | 0.721±0.011 | 0.984±0.011 | 0.797±0.000 | 0.635±0.000 |
| library-aware, library removed | 68 | 0.889±0.059 / 0.010±0.006 / 0.100±0.055 | 0.572±0.019 | 0.764±0.013 | 1.000±0.000 | 0.797±0.000 | 0.635±0.000 |

library-aware − unfiltered (same set of non-library functions), n = 10 pairs:
- Δ payload = +0.140 (p = 0.0488)
- Δ other = -0.046 (p = 0.275)
- Δ ap = +0.043 (p = 0.00195)
- Δ auc = +0.002 (p = 1)
- Δ hit5 = +0.016 (p = 0.00781)
- AP library-aware − AP function size = -0.033 (p = 0.00195)
- AP library-aware − AP random = +0.130 (p = 0.00195)

## x86

| Setting | n GT files/seed | Share payload / helper / library | AUC | AP | Hit@5 | AP function size | AP random |
|---|---|---|---|---|---|---|---|
| unfiltered, all functions | 36 | 0.062±0.012 / 0.002±0.003 / 0.936±0.015 | 0.501±0.026 | 0.388±0.025 | 0.089±0.054 | 0.420±0.000 | 0.197±0.000 |
| unfiltered, library removed | 36 | 0.408±0.078 / 0.112±0.056 / 0.479±0.046 | 0.589±0.044 | 0.657±0.020 | 0.922±0.050 | 0.695±0.000 | 0.547±0.000 |
| library-aware, library removed | 36 | 0.627±0.190 / 0.147±0.236 / 0.226±0.049 | 0.621±0.023 | 0.677±0.016 | 0.964±0.019 | 0.695±0.000 | 0.547±0.000 |

library-aware − unfiltered (same set of non-library functions), n = 10 pairs:
- Δ payload = +0.219 (p = 0.00977)
- Δ other = -0.254 (p = 0.00195)
- Δ ap = +0.020 (p = 0.0645)
- Δ auc = +0.032 (p = 0.0195)
- Δ hit5 = +0.042 (p = 0.0156)
- AP library-aware − AP function size = -0.018 (p = 0.00391)
- AP library-aware − AP random = +0.130 (p = 0.00195)

## POOLED

| Setting | n GT files/seed | Share payload / helper / library | AUC | AP | Hit@5 | AP function size | AP random |
|---|---|---|---|---|---|---|---|
| unfiltered, all functions | 211 | 0.225±0.240 / 0.002±0.004 / 0.774±0.241 | 0.520±0.033 | 0.453±0.081 | 0.415±0.313 | 0.490±0.099 | 0.226±0.066 |
| unfiltered, library removed | 211 | 0.603±0.219 / 0.121±0.130 / 0.276±0.161 | 0.523±0.065 | 0.682±0.040 | 0.970±0.043 | 0.766±0.051 | 0.600±0.043 |
| library-aware, library removed | 211 | 0.710±0.223 / 0.145±0.207 / 0.146±0.082 | 0.540±0.070 | 0.704±0.055 | 0.992±0.017 | 0.766±0.051 | 0.600±0.043 |

library-aware − unfiltered (same set of non-library functions), n = 50 pairs:
- Δ payload = +0.107 (p = 0.000111)
- Δ other = -0.131 (p = 1.26e-07)
- Δ ap = +0.022 (p = 0.00012)
- Δ auc = +0.016 (p = 0.0236)
- Δ hit5 = +0.022 (p = 3.93e-07)
- AP library-aware − AP function size = -0.063 (p = 3.2e-07)
- AP library-aware − AP random = +0.104 (p = 2.1e-09)

