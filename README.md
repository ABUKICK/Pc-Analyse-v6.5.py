🖥️ PC Analysis Tool / PC-Analyse-Tool

🇬🇧 English | 🇩🇪 Deutsch

A fast, lightweight, and secure desktop tool to analyze disk space hogs, drive details, and startup entries on Windows — written in pure Python (standard library only, no external installations required).
⚠️ Important Disclaimer & Safety Notice

    Experimental Software – Use at your own risk!

    This tool is designed strictly for analysis, review, and visualization of system and storage data. It performs no automated write, delete, or system modifications.

        Personal Responsibility: You are solely responsible for what you delete or modify on your PC.

        Never Delete System Files: Using the Explorer shortcuts gives you direct access to directories. Never delete files or folders in protected system areas (like C:\Windows, Program Files, system files like pagefile.sys, or registry keys) unless you know exactly what you are doing.

        Sensitive areas are actively marked with warnings (⛔ / ⚠).

        The author assumes no liability for data loss, system crashes, or malfunctions caused by manual user actions.

✨ Features

    Disk Space Overview: Displays all drives, percentage usage, free space, and hardware details (SSD/HDD, model, bus type, health, and TRIM status via PowerShell).

    Startup Analysis: Lists all startup programs from the registry and startup folders, automatically detecting missing program files (often leftovers from uninstalled apps).

    Largest Folders & File Scanner: Multithreaded folder analysis for maximum speed without freezing the UI. Includes sortable tables, age indicators, right-click context menus, and CSV/text report exports.

🚀 Quick Start
Bash

python "Pc Analyse v6.5.py"

🇩🇪 Deutsch

Ein schnelles, leichtgewichtiges und sicheres Desktop-Tool zur Analyse von Speicherplatzfressern, Laufwerksdetails und Autostart-Einträgen unter Windows – geschrieben in purem Python (nur Standardbibliothek, keine externen Installationen nötig).
⚠️ Wichtiger Haftungsausschluss & Sicherheitshinweis

    Experimentelle Software – Nutzung auf eigene Gefahr!

    Dieses Tool dient ausschließlich der Analyse, Überprüfung und Visualisierung von System- und Speicherdaten. Es führt keinerlei automatische Schreib-, Lösch- oder Systemänderungen am Betriebssystem durch.

        Eigenverantwortung: Jeder Nutzer ist selbst dafür verantwortlich, was er auf seinem PC löscht oder verändert.

        Keine Systemdateien löschen: Über die Explorer-Verknüpfungen hast du direkten Zugriff auf Verzeichnisse. Lösche niemals Dateien oder Ordner in geschützten Bereichen (wie C:\Windows, Program Files, Systemdateien oder Registry-Schlüsseln), es sei denn, du weißt exakt, was du tust.

        Sensible Bereiche werden im Tool aktiv mit Warnhinweisen (⛔ / ⚠) markiert.

        Der Autor übernimmt keinerlei Haftung für Datenverlust, Systemabstürze oder Fehlfunktionen, die durch manuelle Eingriffe des Nutzers entstehen.

✨ Features

    Speicherplatz-Übersicht: Zeigt alle Laufwerke, Belegung in Prozent, freien Speicher sowie hardwarenahe Laufwerksdetails (SSD/HDD, Modell, Bus-Typ, Zustand und TRIM-Status via PowerShell) an.

    Autostart-Analyse: Listet alle Autostart-Programme aus Registry und Autostart-Ordnern auf und erkennt automatisch fehlende Programmdateien (oft Reste alter Deinstallationen).

    Größte Ordner & Dateien (Scanner): Multithreaded Ordner-Analyse für maximale Geschwindigkeit, ohne dass die Benutzeroberfläche einfriert. Inklusive sortierbarer Tabellen, Altersanzeige, Rechtsklick-Menüs und Export-Funktion (CSV/Text).

🚀 Schnellstart
Bash

python "Pc Analyse v6.5.py"

🔒 Privacy & Security / Datenschutz & Sicherheit

    100% Local: Runs entirely locally on your machine. No telemetry, no cloud services, no data transfer. / Läuft zu 100 % lokal auf deinem Computer. Keine Telemetrie, keine Cloud, keine Datenübertragung.

📜 License / Lizenz

Licensed under the MIT License.
