# Script to fix all dispatch tables to use proper function pointer casting
$file = "src\dispatch.rs"
$content = Get-Content $file -Raw

# Replace the pattern: word as *const c_void)
# With: unsafe { std::mem::transmute(word as *const ()) })
$pattern = '([a-z_:]+) as \*const c_void\)'
$replacement = 'unsafe { std::mem::transmute($1 as *const ()) })'

$newContent = $content -replace $pattern, $replacement

Set-Content $file $newContent -NoNewline
Write-Host "Fixed dispatch.rs"
