# cy6er-ADMKS5

## Deskripsi Proyek
**cy6er-ADMKS5** merupakan sebuah sistem aplikasi yang dirancang untuk mendukung proses **monitoring, manajemen, dan pencatatan aktivitas sistem** dengan pendekatan terpusat.  
Aplikasi ini memanfaatkan backend berbasis Python, komponen frontend statis, serta sistem logging yang terintegrasi dengan **Wazuh Dashboard** sebagai solusi *Security Information and Event Management (SIEM)*.

Sistem ini ditujukan untuk membantu administrator dalam memantau aktivitas sistem, mendeteksi potensi ancaman, serta menganalisis log secara terstruktur dan real-time.

---

## Tujuan Proyek
Tujuan utama dari pengembangan proyek ini adalah:
- Menyediakan sistem monitoring dan pencatatan aktivitas sistem secara terpusat
- Mengintegrasikan sistem keamanan berbasis **Wazuh** untuk analisis log dan deteksi ancaman
- Mempermudah administrator dalam memantau kondisi sistem melalui dashboard
- Mendukung pengelolaan log dan data sistem secara terstruktur
- Menjadi media pembelajaran dan pengembangan sistem keamanan informasi

---

## Fitur Utama
Beberapa fitur utama yang disediakan dalam sistem ini antara lain:
- Backend server berbasis Python
- Penyimpanan dan pengelolaan log sistem
- Integrasi dengan **Wazuh Agent dan Wazuh Dashboard**
- Monitoring aktivitas dan event keamanan
- Struktur modular untuk pengembangan lanjutan
- Dukungan migrasi sistem / data
- Pemisahan frontend dan backend

---

## Teknologi yang Digunakan
Teknologi yang digunakan dalam proyek ini meliputi:
- **Bahasa Pemrograman**: Python
- **Backend**: Python-based server
- **Frontend**: HTML, CSS, JavaScript (static assets)
- **Logging & Monitoring**: Wazuh
- **Manajemen Dependensi**: `pip` dan `requirements.txt`
- **Version Control**: Git & GitHub
- **Sistem Operasi**: Linux / Windows

---

## Integrasi Wazuh Dashboard
Wazuh digunakan sebagai sistem **SIEM (Security Information and Event Management)** dalam proyek ini.  
Integrasi Wazuh memungkinkan sistem untuk:

- Mengumpulkan log dari server dan komponen sistem
- Menganalisis event keamanan secara real-time
- Menampilkan hasil analisis melalui **Wazuh Dashboard**
- Memberikan notifikasi terhadap aktivitas mencurigakan
- Mendukung audit dan forensik keamanan

Alur integrasi secara umum:
1. Wazuh Agent berjalan pada sistem
2. Log sistem dikirim ke Wazuh Manager
3. Data dianalisis dan ditampilkan pada Wazuh Dashboard
4. Administrator memantau dan menindaklanjuti event keamanan

---

## Arsitektur Sistem
Secara umum, arsitektur sistem terdiri dari:
- **Frontend**: Antarmuka pengguna (folder `public`)
- **Backend Server**: Pengelolaan log dan proses bisnis (folder `server`)
- **Logging System**: Penyimpanan dan pencatatan log (folder `system_log`)
- **Security Layer**: Wazuh Agent & Dashboard
- **Migration Layer**: Pengelolaan perubahan struktur data

Arsitektur ini dirancang modular agar mudah dikembangkan dan diintegrasikan dengan sistem lain.

---

## Struktur Direktori
Berikut struktur direktori utama dalam repository:

cy6er-ADMKS5/
├── pycache/          # Cache Python (otomatis)
├── migration/        # File migrasi sistem atau data
├── public/           # Aset frontend (HTML, CSS, JavaScript)
├── server/           # Source code backend
├── system_log/       # Penyimpanan log sistem
├── .gitignore        # Konfigurasi Git ignore
├── requirements.txt  # Daftar dependency Python
└── README.md         # Dokumentasi proyek
