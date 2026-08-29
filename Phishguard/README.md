# LinkSense: Real-Time Website Safety

LinkSense checks websites in real time and gives you a clear, explainable safety signal before you interact with them.

---

## 🌟 Features

✅ **Real-Time URL Scanning** – Optionally queries a server-side reputation service while keeping provider credentials out of the extension.

✅ **Dynamic Blocking** – Blocks access to flagged websites and redirects users to a secure warning page.

✅ **User-Friendly Popup** – A modern popup interface allows users to toggle protection, view status, and refresh updates.

✅ **Crowdsourced Reporting** – Users can report phishing sites, contributing to a community-driven database of threats.

✅ **Color-Coded Warnings** – Provides clear, visually appealing warnings (🔴 red for malicious, 🟡 yellow for suspicious, 🟢 green for safe).

✅ **Lightweight & Optimized** – Minimal resource usage ensures smooth performance without slowing down your browsing experience.

---

## 🚀 Installation

### 1️⃣ From Chrome Web Store  
- Visit the LinkSense page on the Chrome Web Store.
- Click **"Add to Chrome"** and follow the prompts to install the extension.

### 2️⃣ From Source Code  
```bash
 git clone https://github.com/th-shivam/linksense.git
```
- Open Chrome and navigate to `chrome://extensions/`.
- Enable **Developer Mode** (toggle in the top-right corner).
- Click **Load Unpacked** and select the cloned repository folder.
- LinkSense will now appear in your extensions list!

---

## 🛠️ How It Works

1. **URL Monitoring** – The background script monitors all navigation events in the browser.
2. **Threat Analysis** – Each URL is analyzed locally and can optionally be sent to a configured server-side reputation service.
3. **Blocking Malicious Sites** – If a URL is flagged as malicious or suspicious, it is blocked, and the user is redirected to a secure warning page.
4. **User Interaction** – The popup provides real-time status updates and allows users to toggle protection or refresh the state.

---

## 🎨 Design Highlights

🌌 **Cyberpunk Theme** – A futuristic design with glowing neon accents and smooth animations.  
⚡ **Interactive Animations** – Buttons pulse, indicators glow, and transitions are seamless.  
📱 **Responsive Layout** – Looks great on all screen sizes, ensuring a consistent user experience.  

---

## 📊 Impact

🌍 **Social** – Protects users from phishing scams, identity theft, and financial fraud.  
💰 **Economic** – Reduces costs associated with cybercrime and enhances business security.  
♻️ **Environmental** – Optimized for energy efficiency, minimizing resource usage.  

---

## 🔧 Development Setup

### Prerequisites
- **Node.js** (optional, for local testing)
- **Chrome Browser** (or other supported browsers like Firefox)
- An optional reputation backend that stores any VirusTotal or provider credentials server-side

### Steps
1. Configure `reputationBackendUrl` in extension storage or a managed policy with your HTTPS backend endpoint.
2. Keep VirusTotal and other provider credentials exclusively on that backend; never put them in extension files.
3. Run the extension locally by following the **Installation** steps above. Without a backend, LinkSense uses local analysis and cached results.

---

## 🤝 Contributing

We welcome contributions from the community! Here’s how you can help:

📌 **Report Bugs** – Open an issue on GitHub if you encounter any problems.  
💡 **Suggest Features** – Share your ideas for new features or improvements.  
🔧 **Submit PRs** – Fork the repository, make your changes, and submit a pull request.  

Please adhere to our **Code of Conduct** when contributing.

---

## 📜 License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

---

## 🙌 Acknowledgments

🔍 **VirusTotal** – For providing the powerful API used for URL scanning.  
🌐 **Chrome Extensions Team** – For their excellent documentation and support for Manifest V3.  
🛠️ **Open Source Community** – For inspiration and resources that helped shape this project.  

---

## 📢 Feedback & Support

💌 **Email:** [anotnet.shivam@gmail.com](mailto:anotnet.shivam@gmail.com)  
🐦 **Twitter:** [@LinkSenseApp](https://twitter.com/LinkSenseApp)
📌 **GitHub Issues:** Open an issue in this repository.  

---

## 🌐 Stay Safe Online

With **LinkSense**, you get a clearer signal before trusting an unfamiliar link.

---

## 📸 Screenshots

### 🖥️ Popup Interface  
![Popup Interface](icons/pop_up.png)

  

### 🚫 Blocked Page  
![Blocked Page](icons/blocked_page.png)  

---

## 📣 Follow Us

⭐ **Star this repository** to show your support!  
🔗 **Share with friends** who care about online safety.  
📢 **Spread the word** about LinkSense on social media.

Thank you for choosing **LinkSense**.

