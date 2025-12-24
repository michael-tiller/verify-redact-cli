@echo off
setlocal enabledelayedexpansion

set SAMPLES=.\samples
set DENYLIST=denylist.txt

python -m src "%SAMPLES%\*.pdf" --denyfile "%SAMPLES%\%DENYLIST%" --strict --ocr=auto

pause
