#!/bin/bash

# Copyright (c) 2026 Hamad hossen hamad Al-Warfali
# Licensed under the MIT License.

# مدة الحظر بالثواني (مثلاً ساعتين = 7200 ثانية)
BLOCK_TIME=7200

# ملفات السجلات
LOG="/home/ubuntu/Desktop/snort_blocked.log"

# تأكد من وجود ملفات السجل
touch "$LOG"

# واجهة الشبكة التي يعمل عليها Snort (عدّل حسب جهازك)
INTERFACE="br0"


(
    while true; do
        cp "$LOG" /tmp/tmp_block_log.txt 2>/dev/null
        while read -r entry; do
            ip=$(echo "$entry" | awk '{print $1}')

            # تأكد أن السطر يحتوي على IP صالح فقط
            if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                if ! iptables -t raw -C PREROUTING -s "$ip" -j DROP 2>/dev/null; then
                    echo "[✓] تم رفع الحظر يدويًا عن $ip - سيتم حذفه من السجلات"
                    sed -i "/$ip/d" "$LOG"
                   
                fi
            fi
        done < /tmp/tmp_block_log.txt
	: > /tmp/tmp_block_log.txt
        sleep 5
    done
) &

# شغل Snort 3 مع إخراج التنبيهات على stdout بصيغة alert_fast
snort -c /etc/snort/snort.lua -i "$INTERFACE" -q | while read -r line; do

    # استخرج أول IP مصدر من التنبيه
    SRC_IP=$(echo "$line" | grep -oP '\d+\.\d+\.\d+\.\d+' | head -n 1)

    # تحقق أن IP موجود وغير داخلي وغير محظور مسبقًا
    if [[ -n "$SRC_IP" ]] && [[ ! "$SRC_IP" =~ ^192\.168\.1\.[0-9]{1,3}$ ]] && ! iptables -t raw -C PREROUTING -s "$SRC_IP" -j DROP 2>/dev/null; then
        echo "[!] اكتشاف هجوم من $SRC_IP - حظره الآن"
        iptables -t raw -A PREROUTING -s "$SRC_IP" -j DROP

	# استخرج نوع الباكت (TCP, UDP, ICMP)
	PACKET_TYPE=$(echo "$line" | grep -oE '\b(ICMP|UDP|TCP)\b' | head -n 1)

	# استخدم "UNKNOWN" إذا لم يتم التعرف على نوع الباكت
	if [[ -z "$PACKET_TYPE" ]]; then
    		PACKET_TYPE="UNKNOWN"
	fi


        # سجل الوقت في ملف الحظر المؤقت
        echo "$SRC_IP $(date +%s) $PACKET_TYPE" >> "$LOG"

        # أضف IP إلى ملف القائمة العامة للمحظورين
        

        # جدولة إزالة الحظر بعد المدة المحددة
        (
            sleep "$BLOCK_TIME"
            iptables -t raw -D PREROUTING -s "$SRC_IP" -j DROP
            sed -i "/$SRC_IP/d" "$LOG"

            echo "[✓] تم رفع الحظر عن $SRC_IP بعد انتهاء المدة"
        ) &
    fi
done
