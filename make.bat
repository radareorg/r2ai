@echo off
setlocal

:check_error
if %errorlevel% neq 0 (
    echo Error encountered, exiting script.
    exit /b %errorlevel%
)

IF NOT EXIST "venv" (
  python3 -m venv venv
  call :check_error
  call venv\Scripts\activate.bat
  call :check_error
  pip install -r requirements.txt
  call :check_error
) ELSE (
  call venv\Scripts\activate.bat
  call :check_error
)
python main.py
call :check_error

endlocal
