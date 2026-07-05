"""
╔════════════════════════════════════════════════════════════════╗
║           WiFi Security Analysis Tool for Windows 10           ║
║                                                                ║
║                    ساخته شده توسط: محمد سلیمانی                 ║
║                     Built by: Mohammad Soleimani               ║
║                                                                ║
║              Educational tool for network security             ║
║                                                                ║
║          ⚠️ FOR AUTHORIZED TESTING ONLY ⚠️                     ║
║          ⚠️ USE ON YOUR OWN NETWORKS OR WITH PERMISSION ⚠️    ║
╚════════════════════════════════════════════════════════════════╝
"""

import customtkinter as ctk
from tkinter import messagebox
import subprocess
import re
import json
from datetime import datetime
from typing import List, Dict, Optional
import threading
import os

# Configure CustomTkinter appearance
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# Security level colors
SECURITY_COLORS = {
    "Excellent": "#00FF00",
    "Strong": "#7FFF00",
    "Good": "#FFD700",
    "Weak": "#FF8C00",
    "Critical": "#FF0000",
    "Unknown": "#808080"
}

def get_wifi_networks() -> List[Dict]:
    """Get available WiFi networks using Windows netsh command"""
    networks = []
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='ignore'
        )
        output = result.stdout
        
        current_network = {}
        for line in output.split('\n'):
            line = line.strip()
            
            if "SSID" in line and ":" in line and "BSSID" not in line:
                if current_network:
                    networks.append(current_network)
                ssid = line.split(":", 1)[1].strip()
                current_network = {"SSID": ssid, "Signal": 0, "Channel": "N/A", 
                                   "Security": "Unknown", "Auth": []}
            
            elif "Signal" in line and ":" in line:
                try:
                    signal = line.split(":", 1)[1].strip().replace("%", "")
                    current_network["Signal"] = int(signal)
                except:
                    pass
            
            elif "Channel" in line and ":" in line:
                try:
                    channel = line.split(":", 1)[1].strip()
                    current_network["Channel"] = channel
                except:
                    pass
            
            elif "Authentication" in line and ":" in line:
                auth = line.split(":", 1)[1].strip()
                if auth not in current_network["Auth"]:
                    current_network["Auth"].append(auth)
        
        if current_network:
            networks.append(current_network)
            
    except Exception as e:
        print(f"Error getting WiFi networks: {e}")
    
    return networks

def get_saved_wifi_profiles() -> List[Dict]:
    """Get saved WiFi profiles on the system"""
    profiles = []
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "profiles"],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='ignore'
        )
        output = result.stdout
        
        for line in output.split('\n'):
            if "All User Profile" in line and ":" in line:
                profile_name = line.split(":", 1)[1].strip()
                # Get details for each profile
                detail_result = subprocess.run(
                    ["netsh", "wlan", "show", "profile", f"name={profile_name}", "key=clear"],
                    capture_output=True,
                    text=True,
                    encoding='utf-8',
                    errors='ignore'
                )
                detail_output = detail_result.stdout
                
                security = "Unknown"
                auth = []
                for dline in detail_output.split('\n'):
                    if "Authentication" in dline and ":" in dline:
                        auth.append(dline.split(":", 1)[1].strip())
                    if "Security" in dline and "key" not in dline.lower() and ":" in dline:
                        security = dline.split(":", 1)[1].strip()
                
                profiles.append({
                    "name": profile_name,
                    "security": security,
                    "auth": auth
                })
    except Exception as e:
        print(f"Error getting WiFi profiles: {e}")
    
    return profiles

def analyze_security(network: Dict) -> Dict:
    """Analyze the security level of a WiFi network"""
    security = network.get("Security", "Unknown") or network.get("auth", ["Unknown"])[0] if network.get("auth") else "Unknown"
    auth_methods = network.get("Auth", []) or network.get("auth", [])
    
    # Determine security level
    if not auth_methods or "Open" in str(auth_methods):
        return {
            "level": "Critical",
            "description": "شبکه بدون رمز - بسیار ناامن",
            "recommendations": [
                "⚠️ این شبکه رمز ندارد!",
                "🔒 فوراً رمز قوی فعال کنید",
                "📡 از VPN استفاده کنید",
                "💳 اطلاعات حساس را منتقل نکنید"
            ]
        }
    
    # Check for WPA3
    if any("WPA3" in str(auth) for auth in auth_methods):
        return {
            "level": "Excellent",
            "description": "امنیت WPA3 - بهترین حالت",
            "recommendations": [
                "✅ پروتکل امنیتی WPA3 فعال است",
                "🔐 از رمزهای پیچیده استفاده کنید",
                "🔄 رمز را به صورت دوره‌ای تغییر دهید"
            ]
        }
    
    # Check for WPA2
    if any("WPA2" in str(auth) for auth in auth_methods):
        if "WPA2-Enterprise" in str(auth_methods):
            return {
                "level": "Strong",
                "description": "WPA2-Enterprise - بسیار امن",
                "recommendations": [
                    "✅ امنیت بالا با احراز هویت سازمانی",
                    "🔐 از 802.1X استفاده می‌شود",
                    "👥 مدیریت مرکزی کاربران"
                ]
            }
        else:
            return {
                "level": "Good",
                "description": "WPA2-Personal - امنیت خوب",
                "recommendations": [
                    "✅ رمزگذاری AES فعال است",
                    "🔐 رمز قوی با حداقل 12 کاراکتر",
                    "📱 فریمور را بروز نگه دارید",
                    "🔄 رمز را هر 6 ماه تغییر دهید"
                ]
            }
    
    # Check for WPA
    if any("WPA" in str(auth) for auth in auth_methods):
        return {
            "level": "Weak",
            "description": "WPA - قدیمی و دارای آسیب‌پذیری",
            "recommendations": [
                "⚠️ WPA منسوخ شده است",
                "🔄 به WPA2 یا WPA3 ارتقا دهید",
                "📡 روتر را تعویض یا بروز کنید"
            ]
        }
    
    # Check for WEP
    if any("WEP" in str(auth) for auth in auth_methods):
        return {
            "level": "Critical",
            "description": "WEP - کاملاً ناامن",
            "recommendations": [
                "🚨 WEP به راحتی قابل شکستن است!",
                "🔄 فوراً به WPA2/WPA3 ارتقا دهید",
                "📞 با ISP خود تماس بگیرید"
            ]
        }
    
    return {
        "level": "Unknown",
        "description": "نوع امنیت نامشخص",
        "recommendations": ["❓ اطلاعات امنیتی در دسترس نیست"]
    }

def get_signal_strength(signal: int) -> str:
    """Convert signal percentage to quality description"""
    if signal >= 80:
        return "عالی 📶📶📶📶"
    elif signal >= 60:
        return "خوب 📶📶📶"
    elif signal >= 40:
        return "متوسط 📶📶"
    elif signal >= 20:
        return "ضعیف 📶"
    else:
        return "خیلی ضعیف 📶"

class WiFiSecurityTool(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        self.title("🔒 WiFi Security Analyzer - ساخته شده توسط محمد سلیمانی")
        self.geometry("1100x750")
        
        # Watermark in window
        self.watermark_label = ctk.CTkLabel(
            self,
            text="🔒 ساخته شده توسط: محمد سلیمانی",
            font=ctk.CTkFont(size=9),
            text_color=("gray40", "gray60")
        )
        self.watermark_label.place(relx=1.0, rely=1.0, anchor="se", x=-10, y=-5)
        
        # Main containers
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        
        # Header
        self.header = ctk.CTkFrame(self, height=80)
        self.header.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 5))
        self.header.grid_columnconfigure(0, weight=1)
        
        self.title_label = ctk.CTkLabel(
            self.header,
            text="🛡️ WiFi Security Analyzer",
            font=ctk.CTkFont(size=24, weight="bold")
        )
        self.title_label.grid(row=0, column=0, pady=15)
        
        self.subtitle_label = ctk.CTkLabel(
            self.header,
            text="ابزار تشخیصی و آموزشی امنیت شبکه وای‌فای | فقط برای شبکه‌های مجاز",
            font=ctk.CTkFont(size=12),
            text_color=("orange", "orange")
        )
        self.subtitle_label.grid(row=1, column=0, pady=(0, 10))
        
        # Control buttons
        self.button_frame = ctk.CTkFrame(self.header)
        self.button_frame.grid(row=2, column=0, pady=5)
        
        self.scan_btn = ctk.CTkButton(
            self.button_frame,
            text="🔍 اسکن شبکه‌ها",
            command=self.scan_networks,
            width=150,
            height=35,
            fg_color="#2FA572"
        )
        self.scan_btn.grid(row=0, column=0, padx=5)
        
        self.profiles_btn = ctk.CTkButton(
            self.button_frame,
            text="💾 پروفایل‌های ذخیره‌شده",
            command=self.show_profiles,
            width=150,
            height=35,
            fg_color="#3B82F6"
        )
        self.profiles_btn.grid(row=0, column=1, padx=5)
        
        self.refresh_btn = ctk.CTkButton(
            self.button_frame,
            text="🔄 بروزرسانی",
            command=self.scan_networks,
            width=100,
            height=35,
            fg_color="#6B7280"
        )
        self.refresh_btn.grid(row=0, column=2, padx=5)
        
        self.export_btn = ctk.CTkButton(
            self.button_frame,
            text="📄 خروجی گرفتن",
            command=self.export_report,
            width=120,
            height=35,
            fg_color="#8B5CF6"
        )
        self.export_btn.grid(row=0, column=3, padx=5)
        
        # Main content area
        self.main_frame = ctk.CTkFrame(self)
        self.main_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=5)
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_columnconfigure(1, weight=1)
        self.main_frame.grid_rowconfigure(0, weight=1)
        
        # Network list (left)
        self.network_list_frame = ctk.CTkFrame(self.main_frame)
        self.network_list_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 5))
        self.network_list_frame.grid_columnconfigure(0, weight=1)
        
        self.network_label = ctk.CTkLabel(
            self.network_list_frame,
            text="📡 شبکه‌های وای‌فای یافت‌شده",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        self.network_label.grid(row=0, column=0, pady=10)
        
        # Scrollable network list
        self.network_scroll = ctk.CTkScrollableFrame(
            self.network_list_frame,
            height=500
        )
        self.network_scroll.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        self.network_scroll.grid_columnconfigure(0, weight=1)
        
        # Details panel (right)
        self.details_frame = ctk.CTkFrame(self.main_frame)
        self.details_frame.grid(row=0, column=1, sticky="nsew", padx=(5, 0))
        self.details_frame.grid_columnconfigure(0, weight=1)
        
        self.details_label = ctk.CTkLabel(
            self.details_frame,
            text="📋 جزئیات امنیتی",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        self.details_label.grid(row=0, column=0, pady=10)
        
        # Details scrollable area
        self.details_scroll = ctk.CTkScrollableFrame(
            self.details_frame,
            height=500
        )
        self.details_scroll.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        self.details_scroll.grid_columnconfigure(0, weight=1)
        
        # Status bar
        self.status_bar = ctk.CTkFrame(self, height=30)
        self.status_bar.grid(row=2, column=0, sticky="ew", padx=10, pady=(5, 10))
        self.status_bar.grid_columnconfigure(0, weight=1)
        
        self.status_label = ctk.CTkLabel(
            self.status_bar,
            text="برای شروع روی 'اسکن شبکه‌ها' کلیک کنید",
            font=ctk.CTkFont(size=11)
        )
        self.status_label.grid(row=0, column=0)
        
        # Initial message
        self.show_welcome_message()
    
    def show_welcome_message(self):
        """Show welcome message in network list"""
        for widget in self.network_scroll.winfo_children():
            widget.destroy()
        
        welcome = ctk.CTkLabel(
            self.network_scroll,
            text="🔒 WiFi Security Analyzer\n\n"
                 "این ابزار برای:\n"
                 "• بررسی امنیت شبکه وای‌فای شما\n"
                 "• شناسایی شبکه‌های ناامن\n"
                 "• دریافت توصیه‌های امنیتی\n\n"
                 "━━━━━━━━━━━━━━━━━━━━━━━\n\n"
                 "👨‍💻 ساخته شده توسط: محمد سلیمانی\n\n"
                 "⚠️ هشدار: فقط روی شبکه‌های مجاز استفاده کنید!\n\n"
                 "روی 'اسکن شبکه‌ها' کلیک کنید...",
            font=ctk.CTkFont(size=13),
            justify="center"
        )
        welcome.grid(row=0, column=0, padx=20, pady=50)
    
    def show_loading(self):
        """Show loading indicator"""
        for widget in self.network_scroll.winfo_children():
            widget.destroy()
        
        loading = ctk.CTkLabel(
            self.network_scroll,
            text="🔄 در حال اسکن شبکه‌ها...",
            font=ctk.CTkFont(size=14),
            justify="center"
        )
        loading.grid(row=0, column=0, padx=20, pady=50)
        
        loading2 = ctk.CTkLabel(
            self.network_scroll,
            text="⏳ لطفاً صبر کنید...",
            font=ctk.CTkFont(size=12),
            text_color=("gray", "gray"),
            justify="center"
        )
        loading2.grid(row=1, column=0, pady=10)
        
        self.update()
    
    def scan_networks(self):
        """Scan for WiFi networks in a separate thread"""
        self.show_loading()
        self.status_label.configure(text="در حال اسکن شبکه‌ها...")
        
        thread = threading.Thread(target=self._scan_networks_thread)
        thread.daemon = True
        thread.start()
    
    def _scan_networks_thread(self):
        """Background thread for network scanning"""
        networks = get_wifi_networks()
        self.after(0, lambda: self.display_networks(networks))
    
    def display_networks(self, networks: List[Dict]):
        """Display the scanned networks"""
        for widget in self.network_scroll.winfo_children():
            widget.destroy()
        
        for widget in self.details_scroll.winfo_children():
            widget.destroy()
        
        if not networks:
            no_network = ctk.CTkLabel(
                self.network_scroll,
                text="❌ هیچ شبکه‌ای یافت نشد!\n\n"
                     "بررسی کنید:\n"
                     "• آداپتور وای‌فای فعال است؟\n"
                     "• در محدوده شبکه هستید؟",
                font=ctk.CTkFont(size=13),
                justify="center"
            )
            no_network.grid(row=0, column=0, padx=20, pady=50)
            self.status_label.configure(text="هیچ شبکه‌ای یافت نشد")
            return
        
        # Store networks for reference
        self.networks = networks
        
        for idx, network in enumerate(networks):
            analysis = analyze_security(network)
            color = SECURITY_COLORS.get(analysis["level"], "#808080")
            
            # Network card
            card = ctk.CTkFrame(self.network_scroll, fg_color=("#2a2a2a", "#1a1a1a"))
            card.grid(row=idx, column=0, sticky="ew", padx=5, pady=3)
            card.grid_columnconfigure(0, weight=1)
            
            # Header with security indicator
            header_frame = ctk.CTkFrame(card, fg_color="transparent")
            header_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=(8, 0))
            
            # Security indicator
            indicator = ctk.CTkLabel(
                header_frame,
                text="●",
                font=ctk.CTkFont(size=18),
                text_color=color
            )
            indicator.grid(row=0, column=0, padx=(0, 5))
            
            # SSID
            ssid_label = ctk.CTkLabel(
                header_frame,
                text=f"📶 {network.get('SSID', 'Unknown')}",
                font=ctk.CTkFont(size=14, weight="bold")
            )
            ssid_label.grid(row=0, column=1, sticky="w")
            
            # Signal strength
            signal_label = ctk.CTkLabel(
                header_frame,
                text=get_signal_strength(network.get("Signal", 0)),
                font=ctk.CTkFont(size=11),
                text_color=("gray70", "gray50")
            )
            signal_label.grid(row=0, column=2, sticky="e")
            
            # Info row
            info_frame = ctk.CTkFrame(card, fg_color="transparent")
            info_frame.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 8))
            
            auth_text = ", ".join(network.get("Auth", [])) if network.get("Auth") else "نامشخص"
            info_label = ctk.CTkLabel(
                info_frame,
                text=f"🔐 {auth_text} | 📡 کانال {network.get('Channel', 'N/A')} | 📊 {network.get('Signal', 0)}%",
                font=ctk.CTkFont(size=10),
                text_color=("gray60", "gray40")
            )
            info_label.grid(row=0, column=0, sticky="w")
            
            # Security level badge
            level_frame = ctk.CTkFrame(header_frame, fg_color=color, corner_radius=3)
            level_frame.grid(row=0, column=3, padx=(10, 0))
            level_label = ctk.CTkLabel(
                level_frame,
                text=analysis["level"],
                font=ctk.CTkFont(size=9, weight="bold"),
                text_color="black"
            )
            level_label.grid(row=0, column=3, padx=5, pady=2)
            
            # Click handler
            card.bind("<Button-1>", lambda e, n=network, a=analysis: self.show_details(n, a))
            for child in card.winfo_children():
                child.bind("<Button-1>", lambda e, n=network, a=analysis: self.show_details(n, a))
                for subchild in child.winfo_children():
                    subchild.bind("<Button-1>", lambda e, n=network, a=analysis: self.show_details(n, a))
        
        self.status_label.configure(
            text=f"✅ {len(networks)} شبکه یافت شد | {datetime.now().strftime('%H:%M:%S')}"
        )
        
        # Show summary
        self.show_summary(networks)
    
    def show_summary(self, networks: List[Dict]):
        """Show security summary"""
        summary_frame = ctk.CTkFrame(self.details_scroll, fg_color=("#1a3a4a", "#0d2137"))
        summary_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        summary_frame.grid_columnconfigure(0, weight=1)
        
        summary_title = ctk.CTkLabel(
            summary_frame,
            text="📊 خلاصه امنیت شبکه‌ها",
            font=ctk.CTkFont(size=14, weight="bold")
        )
        summary_title.grid(row=0, column=0, pady=(10, 5))
        
        # Count by security level
        counts = {"Critical": 0, "Weak": 0, "Good": 0, "Strong": 0, "Excellent": 0, "Unknown": 0}
        
        for network in networks:
            analysis = analyze_security(network)
            counts[analysis["level"]] = counts.get(analysis["level"], 0) + 1
        
        # Display counts
        row = 1
        for level, count in counts.items():
            if count > 0:
                color = SECURITY_COLORS.get(level, "#808080")
                level_label = ctk.CTkLabel(
                    summary_frame,
                    text=f"● {level}: {count} شبکه",
                    font=ctk.CTkFont(size=11),
                    text_color=color
                )
                level_label.grid(row=row, column=0, pady=2, sticky="w", padx=15)
                row += 1
        
        # Total
        total_label = ctk.CTkLabel(
            summary_frame,
            text=f"━━━━━━━━━━━━━━━━━\n📡 مجموع: {len(networks)} شبکه",
            font=ctk.CTkFont(size=10),
            text_color=("gray60", "gray40")
        )
        total_label.grid(row=row, column=0, pady=(5, 10))
    
    def show_details(self, network: Dict, analysis: Dict):
        """Show detailed security information for a network"""
        for widget in self.details_scroll.winfo_children():
            widget.destroy()
        
        color = SECURITY_COLORS.get(analysis["level"], "#808080")
        
        # Title
        title = ctk.CTkLabel(
            self.details_scroll,
            text=f"🔒 {network.get('SSID', 'Unknown')}",
            font=ctk.CTkFont(size=18, weight="bold")
        )
        title.grid(row=0, column=0, sticky="w", pady=(0, 10))
        
        # Security level
        level_frame = ctk.CTkFrame(self.details_scroll, fg_color=color, corner_radius=5)
        level_frame.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        level_title = ctk.CTkLabel(
            level_frame,
            text=f"سطح امنیت: {analysis['level']}",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="black"
        )
        level_title.grid(row=0, column=0, padx=15, pady=8)
        
        # Description
        desc_label = ctk.CTkLabel(
            self.details_scroll,
            text=f"📝 {analysis['description']}",
            font=ctk.CTkFont(size=12),
            text_color=("gray70", "gray50"),
            justify="left"
        )
        desc_label.grid(row=2, column=0, sticky="w", pady=(0, 15))
        
        # Network details section
        details_title = ctk.CTkLabel(
            self.details_scroll,
            text="📋 اطلاعات شبکه",
            font=ctk.CTkFont(size=14, weight="bold")
        )
        details_title.grid(row=3, column=0, sticky="w", pady=(0, 5))
        
        details = [
            ("📶 نام شبکه (SSID)", network.get('SSID', 'Unknown')),
            ("🔐 نوع احراز هویت", ", ".join(network.get('Auth', ['نامشخص'])) or 'نامشخص'),
            ("📡 کانال", network.get('Channel', 'N/A')),
            ("📊 قدرت سیگنال", f"{network.get('Signal', 0)}% ({get_signal_strength(network.get('Signal', 0))})"),
        ]
        
        for idx, (label, value) in enumerate(details):
            detail_frame = ctk.CTkFrame(self.details_scroll, fg_color=("#2a2a2a", "#1a1a1a"))
            detail_frame.grid(row=4+idx, column=0, sticky="ew", pady=2)
            
            lbl = ctk.CTkLabel(
                detail_frame,
                text=label,
                font=ctk.CTkFont(size=11),
                text_color=("gray60", "gray40"),
                anchor="w"
            )
            lbl.grid(row=0, column=0, sticky="w", padx=10, pady=5)
            
            val = ctk.CTkLabel(
                detail_frame,
                text=str(value),
                font=ctk.CTkFont(size=11, weight="bold"),
                anchor="e"
            )
            val.grid(row=0, column=1, sticky="e", padx=10, pady=5)
        
        # Recommendations section
        rec_start = 4 + len(details) + 1
        rec_title = ctk.CTkLabel(
            self.details_scroll,
            text="💡 توصیه‌های امنیتی",
            font=ctk.CTkFont(size=14, weight="bold")
        )
        rec_title.grid(row=rec_start, column=0, sticky="w", pady=(15, 5))
        
        for idx, rec in enumerate(analysis["recommendations"]):
            rec_label = ctk.CTkLabel(
                self.details_scroll,
                text=rec,
                font=ctk.CTkFont(size=11),
                text_color=color if "⚠️" in rec or "🚨" in rec or "✅" in rec else ("gray80", "gray60"),
                justify="left",
                anchor="w"
            )
            rec_label.grid(row=rec_start+1+idx, column=0, sticky="w", pady=2, padx=10)
        
        # Export button for this network
        exp_row = rec_start + 1 + len(analysis["recommendations"]) + 1
        export_single = ctk.CTkButton(
            self.details_scroll,
            text="📄 خروجی گرفتن از این شبکه",
            command=lambda: self.export_single_network(network, analysis),
            width=200,
            height=35,
            fg_color="#8B5CF6"
        )
        export_single.grid(row=exp_row, column=0, pady=15)
    
    def show_profiles(self):
        """Show saved WiFi profiles"""
        for widget in self.network_scroll.winfo_children():
            widget.destroy()
        
        for widget in self.details_scroll.winfo_children():
            widget.destroy()
        
        self.status_label.configure(text="در حال دریافت پروفایل‌های ذخیره‌شده...")
        
        thread = threading.Thread(target=self._show_profiles_thread)
        thread.daemon = True
        thread.start()
    
    def _show_profiles_thread(self):
        """Background thread for getting profiles"""
        profiles = get_saved_wifi_profiles()
        self.after(0, lambda: self.display_profiles(profiles))
    
    def display_profiles(self, profiles: List[Dict]):
        """Display saved WiFi profiles"""
        self.status_label.configure(text=f"پروفایل‌های ذخیره‌شده: {len(profiles)}")
        
        if not profiles:
            no_profile = ctk.CTkLabel(
                self.network_scroll,
                text="❌ هیچ پروفایل ذخیره‌شده‌ای یافت نشد!",
                font=ctk.CTkFont(size=13),
                justify="center"
            )
            no_profile.grid(row=0, column=0, padx=20, pady=50)
            return
        
        for idx, profile in enumerate(profiles):
            analysis = analyze_security(profile)
            color = SECURITY_COLORS.get(analysis["level"], "#808080")
            
            card = ctk.CTkFrame(self.network_scroll, fg_color=("#2a2a2a", "#1a1a1a"))
            card.grid(row=idx, column=0, sticky="ew", padx=5, pady=3)
            card.grid_columnconfigure(0, weight=1)
            
            # Profile info
            header_frame = ctk.CTkFrame(card, fg_color="transparent")
            header_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=8)
            
            indicator = ctk.CTkLabel(
                header_frame,
                text="●",
                font=ctk.CTkFont(size=18),
                text_color=color
            )
            indicator.grid(row=0, column=0, padx=(0, 5))
            
            name_label = ctk.CTkLabel(
                header_frame,
                text=f"💾 {profile.get('name', 'Unknown')}",
                font=ctk.CTkFont(size=14, weight="bold")
            )
            name_label.grid(row=0, column=1, sticky="w")
            
            # Security info
            auth_text = ", ".join(profile.get("auth", [])) if profile.get("auth") else profile.get("security", "نامشخص")
            info_label = ctk.CTkLabel(
                header_frame,
                text=f"🔐 {auth_text}",
                font=ctk.CTkFont(size=10),
                text_color=("gray60", "gray40")
            )
            info_label.grid(row=1, column=1, sticky="w", padx=23)
        
        # Show details for first profile
        if profiles:
            analysis = analyze_security(profiles[0])
            self.show_profile_details(profiles[0], analysis)
    
    def show_profile_details(self, profile: Dict, analysis: Dict):
        """Show details for a profile"""
        for widget in self.details_scroll.winfo_children():
            widget.destroy()
        
        color = SECURITY_COLORS.get(analysis["level"], "#808080")
        
        title = ctk.CTkLabel(
            self.details_scroll,
            text=f"💾 {profile.get('name', 'Unknown')}",
            font=ctk.CTkFont(size=18, weight="bold")
        )
        title.grid(row=0, column=0, sticky="w", pady=(0, 10))
        
        level_frame = ctk.CTkFrame(self.details_scroll, fg_color=color, corner_radius=5)
        level_frame.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        level_title = ctk.CTkLabel(
            level_frame,
            text=f"سطح امنیت: {analysis['level']}",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="black"
        )
        level_title.grid(row=0, column=0, padx=15, pady=8)
        
        desc_label = ctk.CTkLabel(
            self.details_scroll,
            text=f"📝 {analysis['description']}",
            font=ctk.CTkFont(size=12),
            text_color=("gray70", "gray50"),
            justify="left"
        )
        desc_label.grid(row=2, column=0, sticky="w", pady=(0, 15))
        
        # Recommendations
        rec_title = ctk.CTkLabel(
            self.details_scroll,
            text="💡 توصیه‌های امنیتی",
            font=ctk.CTkFont(size=14, weight="bold")
        )
        rec_title.grid(row=3, column=0, sticky="w", pady=(15, 5))
        
        for idx, rec in enumerate(analysis["recommendations"]):
            rec_label = ctk.CTkLabel(
                self.details_scroll,
                text=rec,
                font=ctk.CTkFont(size=11),
                text_color=color if "⚠️" in rec or "🚨" in rec or "✅" in rec else ("gray80", "gray60"),
                justify="left",
                anchor="w"
            )
            rec_label.grid(row=4+idx, column=0, sticky="w", pady=2, padx=10)
    
    def export_single_network(self, network: Dict, analysis: Dict):
        """Export single network report"""
        filename = f"wifi_security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        content = f"""
{'='*60}
🔒 WiFi Security Report - Single Network
{'='*60}
📅 Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
👨‍💻 Created by: Mohammad Soleimani (محمد سلیمانی)
{'='*60}

Network SSID: {network.get('SSID', 'Unknown')}
Signal Strength: {network.get('Signal', 0)}%
Channel: {network.get('Channel', 'N/A')}
Authentication: {', '.join(network.get('Auth', ['Unknown']))}

Security Analysis:
- Level: {analysis['level']}
- Description: {analysis['description']}

Recommendations:
{chr(10).join(f"  {rec}" for rec in analysis['recommendations'])}

{'='*60}
🔒 Made by: Mohammad Soleimani (محمد سلیمانی)
{'='*60}
⚠️ FOR AUTHORIZED TESTING ONLY
{'='*60}
"""
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(content)
            messagebox.showinfo("موفق!", f"گزارش ذخیره شد:\n{filename}")
        except Exception as e:
            messagebox.showerror("خطا!", f"خطا در ذخیره:\n{e}")
    
    def export_report(self):
        """Export full security report"""
        if not hasattr(self, 'networks') or not self.networks:
            messagebox.showwarning("هشدار!", "ابتدا شبکه‌ها را اسکن کنید!")
            return
        
        filename = f"wifi_full_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        content = f"""
{'='*70}
🔒 WiFi Security Analysis Report
{'='*70}
📅 Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
👨‍💻 Created by: Mohammad Soleimani (محمد سلیمانی)
{'='*70}

{'='*70}
SECURITY SUMMARY
{'='*70}
Total Networks Found: {len(self.networks)}

"""
        
        # Count by security level
        counts = {}
        for network in self.networks:
            analysis = analyze_security(network)
            level = analysis['level']
            counts[level] = counts.get(level, 0) + 1
        
        for level, count in counts.items():
            content += f"  {level}: {count} networks\n"
        
        content += f"""
{'='*70}
NETWORK DETAILS
{'='*70}
"""
        
        for idx, network in enumerate(self.networks, 1):
            analysis = analyze_security(network)
            content += f"""
Network #{idx}
--------------
SSID: {network.get('SSID', 'Unknown')}
Signal: {network.get('Signal', 0)}%
Channel: {network.get('Channel', 'N/A')}
Auth: {', '.join(network.get('Auth', ['Unknown']))}
Security Level: {analysis['level']}
Description: {analysis['description']}

Recommendations:
{chr(10).join(f"  - {rec}" for rec in analysis['recommendations'])}
"""
        
        content += f"""
{'='*70}
🔒 Made by: Mohammad Soleimani (محمد سلیمانی)
{'='*70}
⚠️ FOR AUTHORIZED TESTING ONLY
⚠️ Use only on networks you own or have permission to test
{'='*70}
"""
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(content)
            messagebox.showinfo("موفق!", f"گزارش کامل ذخیره شد:\n{filename}")
        except Exception as e:
            messagebox.showerror("خطا!", f"خطا در ذخیره:\n{e}")


if __name__ == "__main__":
    app = WiFiSecurityTool()
    app.mainloop()
