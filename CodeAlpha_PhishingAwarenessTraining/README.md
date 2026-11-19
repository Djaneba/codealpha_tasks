# CodeAlpha – Phishing Awareness Training

> **CodeAlpha Cyber Security Internship – Task 2**
> An interactive online training module that teaches employees and students how to recognise and avoid phishing attacks, with hands-on exercises, real-world case studies, a scored final quiz and a certificate of completion.

**Live demo:** `https://Djaneba.github.io/CodeAlpha_PhishingAwarenessTraining/` (see *Deploy* below)

---

## Course content

| # | Module | What the learner does |
|---|---|---|
| 1 | **Introduction** | What phishing is, why it matters (FBI IC3 2024 figures), learning objectives |
| 2 | **Types of phishing** | Email, spear phishing, whaling, smishing, vishing, quishing, BEC, clone phishing → *practice: name that attack* |
| 3 | **Recognising phishing emails** | **Interactive email inspector**: click the 7 red flags hidden in a realistic phishing email; universal red-flag checklist → *practice: phishing or legitimate? (5 messages)* |
| 4 | **Recognising fake websites** | How to read a URL (registered domain vs subdomain), typosquatting, homograph/punycode, the HTTPS padlock myth, cloned login pages, QR codes → *practice: URL detective (6 URLs)* |
| 5 | **Social engineering** | 6 psychological levers (urgency, authority, fear, greed, curiosity, trust) + pretexting, baiting, tailgating, MFA fatigue, deepfakes → *practice: identify the tactic* |
| 6 | **Real-world examples** | Google & Facebook invoice fraud (~$100M), Ubiquiti BEC ($46.7M), Twitter 2020 vishing hack, MGM Resorts 2023 helpdesk attack, Arup 2024 deepfake video call ($25M), each with its lesson |
| 7 | **Best practices** | Personal commitment checklist (11 habits), 6-step incident response *“I think I clicked”*, organisational controls (DMARC, FIDO2, dual approval, simulations) |
| 8 | **Final quiz** | 10 questions with instant feedback and explanations, 80% pass mark, retake option |
| 9 | **Certificate** | Personalised certificate of completion, printable / save as PDF |

## Features

- **Fully interactive:** 4 practice exercises + clickable email inspector + final quiz (30+ graded interactions)
- **Progress tracking:** progress bar and completed-module ticks, saved in the browser (`localStorage`)
- **Responsive:** desktop sidebar, mobile top navigation; tested at 1280px and 390px
- **Accessible:** keyboard navigable, visible focus, ARIA live regions for feedback, 44px touch targets, reduced-motion support
- **Light & dark themes** (follows the system setting)
- **Zero dependencies:** a single `index.html` (HTML + CSS + vanilla JS), works offline, no tracking, no data leaves the browser
- **Safe by design:** all phishing examples use fictional companies (e.g. *SecureBank*) and non-clickable links

## Run it

```bash
git clone https://github.com/Djaneba/CodeAlpha_PhishingAwarenessTraining.git
cd CodeAlpha_PhishingAwarenessTraining
# simply open index.html in your browser, or serve it:
python3 -m http.server 8000      # then visit http://localhost:8000
```

## Deploy on GitHub Pages (free, 1 minute)

1. Push the repository to GitHub.
2. *Settings → Pages → Build and deployment → Source: Deploy from a branch → Branch: `main` / `root` → Save.*
3. After ~1 minute the module is live at `https://Djaneba.github.io/CodeAlpha_PhishingAwarenessTraining/`.

## Project structure

```
CodeAlpha_PhishingAwarenessTraining/
├── index.html      # the complete training module (single file)
└── README.md
```

## Key takeaways taught

1. **Stop, think, verify:** strong emotion + urgency + unusual request = red flag.
2. **Read the real domain** (right before the first single `/`); the padlock doesn't mean safe.
3. **Never log in from a link in a message:** type the address or use the app.
4. **Verify payment / bank-detail / gift-card requests out-of-band** on a known number.
5. **Use a password manager + phishing-resistant MFA** (passkeys / FIDO2 keys).
6. **Report quickly**, even (especially) if you clicked.

## Sources

- FBI Internet Crime Complaint Center – [2024 Internet Crime Report](https://www.ic3.gov/AnnualReport/Reports/2024_IC3Report.pdf) (phishing/spoofing: 193,407 complaints, #1 crime type; total losses $16.6B)
- Public reporting on the case studies: U.S. DOJ (Rimasauskas case), Ubiquiti SEC 8-K filing (2015), NY DFS Twitter investigation report (2020), MGM Resorts SEC 8-K (2023), Arup statements to CNN / Financial Times (2024)
- CISA – [Avoiding Social Engineering and Phishing Attacks](https://www.cisa.gov/news-events/news/avoiding-social-engineering-and-phishing-attacks)

## Author

**Amadou Sanoko Djaneba** – Cyber Security Intern @ CodeAlpha
[GitHub](https://github.com/Djaneba)
