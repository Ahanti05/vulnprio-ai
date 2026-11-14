# Viva and demo guide

## 2-minute demo script
1. **Overview tab:** "Most companies fix bugs by CVSS score. We rank them by real context. Here are 31 bugs on 19 computers; 7 are urgent, 21 are already being exploited by hackers."
2. **How attackers get in:** pick route #1. "A hacker can go Internet → mail server → HR laptop → HR database using these three real CVEs."
3. **Try a fix:** select **F007 (mail-01)**. "One fix removes about half of the risk to our critical systems."
4. **Best fix plan:** "With 5 fixes, CVSS-only removes 0% of the modelled risk; our ranking removes 100%." (Always add: *on our synthetic network.*)
5. **AI predictor:** "Tested on 18,544 unseen 2021 CVEs: 18 of the AI's top 100 picks were really exploited, versus 4 for CVSS."

## Likely questions and short answers

**Q1. What problem does your project solve?**
Teams can't fix every bug at once. CVSS shows general severity but ignores whether the bug is being exploited, how important the computer is, and whether an attacker can reach it. We combine all of these to decide what to fix first.

**Q2. Where exactly is the AI?**
An NLP model reads each CVE's description, plus its CVSS metrics, CWE and vendor, and predicts whether the CVE will be exploited (appear in CISA KEV). It is TF-IDF with class-balanced logistic regression, trained on 35,627 CVEs and tested on 18,544 newer ones.

**Q3. Why logistic regression and not deep learning?**
The data is text plus categories, and positives are rare (about 1%). Logistic regression is fast, hard to overfit, and its weights are explainable: we can show which words raise the exploit probability. XGBoost with SHAP is planned for semester 8 as a comparison.

**Q4. Why a time-based split?**
In real use the model sees *new* CVEs. Training on older CVEs and testing on newer ones simulates that, so it can't "peek at the future".

**Q5. Why is PR-AUC so low (0.084)?**
Only about 1% of CVEs are ever exploited, so random guessing gives about 0.011. Our 0.084 is about 8× random and 3.6× better than CVSS (0.023). With rare events, PR-AUC is always low in absolute terms.

**Q6. What are EPSS and KEV?**
EPSS (from FIRST) gives each CVE a probability of exploitation in the next 30 days. KEV (from CISA) is the official list of CVEs known to be exploited in the wild.

**Q7. If EPSS exists, why build your own model?**
EPSS is a strong signal and we use it. Our model adds a second opinion, works offline, can score brand-new CVEs before EPSS updates, and is our own explainable AI component.

**Q8. How is the attack graph built?**
Nodes are the Internet and every asset. An edge u → v exists only if the network allows u to reach v **and** v has an unpatched, remotely exploitable CVE with high confidentiality or integrity impact. The edge weight is −log(p), so Dijkstra's shortest path gives the most likely attack path.

**Q9. What is a choke point?**
An asset that many attack paths pass through. We also compute a minimum node cut: the smallest set of assets that, if secured, disconnects the Internet from all crown jewels.

**Q10. How does the Fix-First plan work?**
A greedy algorithm. At each step it tries every remaining fix, keeps the one that removes the most crown-jewel risk, and repeats.

**Q11. How did you choose the weights?**
They are documented starting assumptions. The sensitivity study (docs/EXPERIMENTS.md) shows the ranking is fairly stable under random weights (mean Kendall's τ 0.70, compared with 0.47 against CVSS-only). Users can change the weights in the dashboard.

**Q12. Does it scale?**
Yes. On synthetic networks it analysed 2,000 assets and 3,935 findings in under 1 second. Path enumeration is capped because it can grow exponentially; risk uses Dijkstra, which scales well.

**Q13. Is your data real?**
The CVE intelligence (NVD, EPSS, KEV) is real and saved as a dated snapshot. The company network is synthetic, because real company network data is confidential.

**Q14. What are the limitations?**
- The network is synthetic.
- An attack edge is a modelled possibility, not a confirmed exploit.
- KEV is incomplete, so the AI labels contain noise.
- Local privilege escalation is not chained yet.
- Weights are not learned from data.

**Q15. Is this ethical / legal?**
Yes. It is defensive decision-support only: nothing is scanned or exploited, and any real scanning in semester 8 will be on the team's own lab VMs.

**Q16. What will you add in semester 8?**
- XGBoost with SHAP
- a scalability study at larger scale
- real scanner input from our own lab
- MITRE ATT&CK mapping
- an API with login
- public deployment
- a research paper
