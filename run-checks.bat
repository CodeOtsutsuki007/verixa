@echo off
cd /d "c:\Users\Nuelthewave\Desktop\Kayvera PR\verixa"

echo Running typecheck...
call pnpm typecheck
if errorlevel 1 (
    echo Typecheck failed
    exit /b 1
)

echo.
echo Running lint...
call pnpm lint
if errorlevel 1 (
    echo Lint failed
    exit /b 1
)

echo.
echo Running tests (in-memory only, no database required)...
call pnpm test --run 2>&1 | findstr /V "SKIPPED"
if errorlevel 1 (
    echo Tests failed
    exit /b 1
)

echo.
echo Running format check...
call pnpm format:check
if errorlevel 1 (
    echo Format check failed
    exit /b 1
)

echo.
echo All checks passed!
