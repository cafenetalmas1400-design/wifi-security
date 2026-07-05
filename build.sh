#!/bin/bash

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║     🔒 WiFi Security Analyzer - Build Script               ║"
echo "║        ساخته شده توسط: محمد سلیمانی                        ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# ساخت محیط مجازی
echo "🔧 ساخت محیط مجازی..."
python3 -m venv myenv

# فعال کردن
echo "✅ فعال‌سازی محیط مجازی..."
source myenv/bin/activate

# نصب کتابخانه‌ها
echo "📦 نصب کتابخانه‌ها..."
pip install --upgrade pip
pip install customtkinter Pillow pyinstaller

# ساخت EXE
echo ""
echo "🔨 ساخت فایل EXE... (~2-3 دقیقه)"
python -m PyInstaller --onefile --name WiFi_Security_Analyzer --icon=app.ico --noconfirm wifi_security_tool.py

echo ""
if [ -f "dist/WiFi_Security_Analyzer.exe" ]; then
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║                                                           ║"
    echo "║           ✅ ساخت EXE با موفقیت انجام شد!                 ║"
    echo "║                                                           ║"
    echo "║     📁 فایل: dist/WiFi_Security_Analyzer.exe              ║"
    echo "║     👨‍💻 Mohammad Soleimani                                  ║"
    echo "║                                                           ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
else
    echo "❌ ساخت ناموفق!"
fi
