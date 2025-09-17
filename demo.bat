@echo off
color 0A
echo 🚀 SMART CODE VULNERABILITY TRIAGE SYSTEM
echo ========================================
echo        Hackathon Edition v1.0
echo ========================================
echo.

timeout /t 1 /nobreak >nul
echo [1/3] Scanning test file for vulnerabilities...
python main.py --scan test_simple.py
echo.

timeout /t 1 /nobreak >nul
echo [2/3] Generating professional HTML report...
python main.py --scan test_simple.py --report-format html --output reports
echo.

timeout /t 1 /nobreak >nul
echo [3/3] Opening security report in browser...
start "" reports\*.html
echo.

echo 🎉 SUCCESS: Demo completed!
echo 📁 Check the 'reports' folder for detailed findings
echo.
pause
