# Reading list for Chapter 2 (verified 2026-11-08)

Each entry was confirmed on the web (publisher, DBLP, DOAJ, arXiv or the official site): title,
authors, year, venue and link. Read a source before citing it; the one-line notes say what it is
used for, not a full summary.

**Check before quoting figures:** the IC3 2025 report PDF could not be read as text, and the DBIR 2026
phishing percentages came from secondary summaries that disagree. Take any number from those reports
from the PDF itself.

## 1. Scale and impact of phishing
- Verizon (2026). *2026 Data Breach Investigations Report*. https://www.verizon.com/business/resources/reports/dbir/ (social engineering as a breach vector; check figures in the report)
- FBI Internet Crime Complaint Center (2026). *2025 Internet Crime Report*. https://www.ic3.gov/AnnualReport/Reports/2025_IC3Report.pdf (phishing/spoofing as the most-reported category; check figures in the PDF)
- APWG (2026). *Phishing Activity Trends Report, Q4 2025*. https://docs.apwg.org/reports/apwg_trends_report_q4_2025.pdf (volume of phishing attacks per quarter)

## 2. Surveys of ML/DL phishing detection
- Das, A., Baki, S., El Aassal, A., Verma, R., & Dunbar, A. (2020). SoK: A comprehensive reexamination of phishing research from the security perspective. *IEEE Communications Surveys & Tutorials*, 22(1), 671–708. https://arxiv.org/abs/1911.00953
- Do, N. Q., Selamat, A., Krejcar, O., Herrera-Viedma, E., & Fujita, H. (2022). Deep learning for phishing detection: Taxonomy, current challenges and future directions. *IEEE Access*, 10, 36429–36463. https://doi.org/10.1109/ACCESS.2022.3151903
- Zieni, R., Massari, L., & Calzarossa, M. C. (2023). Phishing or not phishing? A survey on the detection of phishing websites. *IEEE Access*, 11, 18499–18519. https://doi.org/10.1109/ACCESS.2023.3247135
- El Aassal, A., Baki, S., Das, A., & Verma, R. M. (2020). An in-depth benchmarking and evaluation of phishing detection research for security needs. *IEEE Access*, 8, 22170–22192. https://doi.org/10.1109/ACCESS.2020.2969780

## 3. Dataset bias, leakage, temporal and concept drift
- Arp, D., Quiring, E., Pendlebury, F., Warnecke, A., Pierazzi, F., Wressnegger, C., Cavallaro, L., & Rieck, K. (2022). Dos and don'ts of machine learning in computer security. *USENIX Security '22*, 3971–3988. https://www.usenix.org/conference/usenixsecurity22/presentation/arp
- Pendlebury, F., Pierazzi, F., Jordaney, R., Kinder, J., & Cavallaro, L. (2019). TESSERACT: Eliminating experimental bias in malware classification across space and time. *USENIX Security '19*, 729–746. https://www.usenix.org/conference/usenixsecurity19/presentation/pendlebury
- Barbero, F., Pendlebury, F., Pierazzi, F., & Cavallaro, L. (2022). Transcending Transcend: Revisiting malware classification in the presence of concept drift. *IEEE S&P 2022*, 1165–1183. https://doi.org/10.1109/SP46214.2022.9833659
- Dalton, T., et al. (2025). PhreshPhish: A real-world, high-quality, large-scale phishing website dataset and benchmark. arXiv:2507.10854 (preprint, not peer-reviewed). https://arxiv.org/abs/2507.10854

## 4. Tree ensembles and transformers
- Chen, T., & Guestrin, C. (2016). XGBoost: A scalable tree boosting system. *KDD '16*, 785–794. https://doi.org/10.1145/2939672.2939785
- Ke, G., et al. (2017). LightGBM: A highly efficient gradient boosting decision tree. *NeurIPS 30*, 3146–3154. https://proceedings.neurips.cc/paper/2017/file/6449f44a102fde848669bdd9eb6b76fa-Paper.pdf
- Sahingoz, O. K., Buber, E., Demir, O., & Diri, B. (2019). Machine learning based phishing detection from URLs. *Expert Systems with Applications*, 117, 345–357. https://doi.org/10.1016/j.eswa.2018.09.029
- Le, H., Pham, Q., Sahoo, D., & Hoi, S. C. H. (2018). URLNet: Learning a URL representation with deep learning for malicious URL detection. arXiv:1802.03162. https://arxiv.org/abs/1802.03162
- Maneriker, P., Stokes, J. W., et al. (2021). URLTran: Improving phishing URL detection using transformers. *IEEE MILCOM 2021*. https://arxiv.org/abs/2106.05256
- Sanh, V., Debut, L., Chaumond, J., & Wolf, T. (2019). DistilBERT, a distilled version of BERT: smaller, faster, cheaper and lighter. NeurIPS 2019 EMC² Workshop. https://arxiv.org/abs/1910.01108

## 5. Threat intelligence, VirusTotal, blocklists
- Zhu, S., et al. (2020). Measuring and modeling the label dynamics of online anti-malware engines. *USENIX Security '20*, 2361–2378. https://www.usenix.org/conference/usenixsecurity20/presentation/zhu
- Peng, P., Yang, L., Song, L., & Wang, G. (2019). Opening the blackbox of VirusTotal: Analyzing online phishing scan engines. *ACM IMC 2019*, 478–485. https://doi.org/10.1145/3355369.3355585
- Oest, A., et al. (2020a). Sunrise to sunset: Analyzing the end-to-end life cycle and effectiveness of phishing attacks at scale. *USENIX Security '20*, 361–377. https://www.usenix.org/conference/usenixsecurity20/presentation/oest-sunrise
- Oest, A., et al. (2020b). PhishTime: Continuous longitudinal measurement of the effectiveness of anti-phishing blacklists. *USENIX Security '20*, 379–396. https://www.usenix.org/conference/usenixsecurity20/presentation/oest-phishtime

## 6. Simulations, training effectiveness, ethics
- Lain, D., Kostiainen, K., & Čapkun, S. (2022). Phishing in organizations: Findings from a large-scale and long-term study. *IEEE S&P 2022*, 842–859. https://doi.org/10.1109/SP46214.2022.9833766
- Ho, G., et al. (2025). Understanding the efficacy of phishing training in practice. *IEEE S&P 2025*, 37–54. https://doi.org/10.1109/SP61157.2025.00076
- Finn, P., & Jakobsson, M. (2007). Designing ethical phishing experiments. *IEEE Technology and Society Magazine*, 26(1), 46–58. https://doi.org/10.1109/MTAS.2007.335565
- Dittrich, D., & Kenneally, E. (2012). *The Menlo Report: Ethical principles guiding information and communication technology research*. US DHS S&T. https://www.caida.org/publications/papers/2012/menlo_report/menlo_report.pdf

## 7. Visual similarity and brand impersonation
- Abdelnabi, S., Krombholz, K., & Fritz, M. (2020). VisualPhishNet: Zero-day phishing website detection by visual similarity. *ACM CCS 2020*, 1681–1698. https://doi.org/10.1145/3372297.3417233
- Lin, Y., et al. (2021). Phishpedia: A hybrid deep learning based approach to visually identify phishing webpages. *USENIX Security '21*, 3793–3810. https://www.usenix.org/conference/usenixsecurity21/presentation/lin
- Liu, R., et al. (2022). Inferring phishing intention via webpage appearance and dynamics: A deep vision based approach. *USENIX Security '22*, 1633–1650. https://www.usenix.org/conference/usenixsecurity22/presentation/liu-ruofan
- Ji, F., et al. (2025). Evaluating the effectiveness and robustness of visual similarity-based phishing detection models. *USENIX Security '25*, 3201–3220. https://www.usenix.org/conference/usenixsecurity25/presentation/ji
- Chiew, K. L., Choo, J. S.-F., Sze, S. N., & Yong, K. S. C. (2018). Leverage website favicon to detect phishing websites. *Security and Communication Networks*, 2018. https://doi.org/10.1155/2018/7251750

No peer-reviewed paper on perceptual hashing of favicons was found; D6 can cite Chiew et al. (2018)
for the favicon as a brand signal, and say the hashing approach itself is this project's choice.

## 8. Calibration and comparing classifiers
- Guo, C., Pleiss, G., Sun, Y., & Weinberger, K. Q. (2017). On calibration of modern neural networks. *ICML 2017*, PMLR 70:1321–1330. https://proceedings.mlr.press/v70/guo17a.html
- Niculescu-Mizil, A., & Caruana, R. (2005). Predicting good probabilities with supervised learning. *ICML 2005*, 625–632. https://doi.org/10.1145/1102351.1102430
- Dietterich, T. G. (1998). Approximate statistical tests for comparing supervised classification learning algorithms. *Neural Computation*, 10(7), 1895–1923. https://doi.org/10.1162/089976698300017197
- Demšar, J. (2006). Statistical comparisons of classifiers over multiple data sets. *JMLR*, 7, 1–30. https://www.jmlr.org/papers/v7/demsar06a.html

Not verified, so not listed: a reference for the bootstrap (Efron & Tibshirani, 1993, is the usual
one; check it before citing).
