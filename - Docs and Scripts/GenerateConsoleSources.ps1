<#
Generate the platform-specific console sources from GenericConsole.cpp.

Run from the repository root with Windows PowerShell:
  powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File ".\- Docs and Scripts\GenerateConsoleSources.ps1"

Optional positional arguments override the input source and output directory:
  powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File ".\- Docs and Scripts\GenerateConsoleSources.ps1" ".\GenericConsole.cpp" "."

When omitted, the input defaults to GenericConsole.cpp in the repository root
and the output directory defaults to the repository root. The script writes
WindowsUTF8Console.cpp, LinuxConsole.cpp, and WindowsWideConsole.cpp there.
Set DEBUG_OUTPUT=1 in the environment to print transformation details.
#>
param(
	[Parameter(Position = 0)] [string] $InputPath,
	[Parameter(Position = 1)] [string] $OutputDirectory
)

$ErrorActionPreference = 'Stop'

function Write-DebugInfo([string] $Message) {
	if ($env:DEBUG_OUTPUT -eq '1') {
		Write-Host $Message
	}
}

function Get-PreprocCountError([string] $Contents, [string] $Symbol) {
	$escaped = [regex]::Escape($Symbol)
	$matcher = "(?m)#[ \t]*((?:if(?:n?def)?)|(?:else)|(?:endif))[ \t]*(?://)?[ \t]*!?$escaped[ \t]*\r?\n"
	$matches = [regex]::Matches($Contents, $matcher)
	$numIfDefs = 0
	$numEndIfs = 0
	foreach ($match in $matches) {
		if ($match.Groups[1].Value.StartsWith('if')) {
			++$numIfDefs
		} elseif ($match.Groups[1].Value -eq 'endif') {
			++$numEndIfs
		}
	}
	if ($numIfDefs -eq 0) {
		return "regex broken for detecting #ifdef $Symbol (none found)."
	}
	if ($numIfDefs -gt $numEndIfs) {
		return "Too many #if(def) $Symbol ($numIfDefs) without enough #endif $Symbol ($numEndIfs)."
	}
	if ($numEndIfs -gt $numIfDefs) {
		return "Too many #endif $Symbol ($numEndIfs) without enough #if(def) $Symbol ($numIfDefs)."
	}
	return $null
}

function Replace-Preproc([string] $Symbol, [bool] $IsPreprocTrue) {
	$countError = Get-PreprocCountError $script:NewFileContents $Symbol
	if ($null -ne $countError) {
		throw $countError
	}

	$escaped = [regex]::Escape($Symbol)
	$matcher = "(?m)^[ \t]*#[ \t]*?if(?<n>n?)(?:def)?[ \t]+(?<x>!?)$escaped\s*\n" +
		"(?<ifsect>(?:.|\n)*?)(?:\n[ \t]*?#[ \t]*?else[ \t]*//[ \t]*!$escaped[ \t]*\n" +
		"(?<elsesect>(?:.|\n)+?))?\n[ \t]*?#[ \t]*?endif[ \t]*?//[ \t]*!?$escaped[ \t]*\n" +
		"(?<afterline>[ \t]*\n)?"

	$evaluator = [Text.RegularExpressions.MatchEvaluator] {
		param($match)
		Write-DebugInfo "---- got match for ${Symbol}:`n$($match.Value)`n----"
		$extra = if ($match.Groups['afterline'].Success) { "`n`n" } else { "`n" }
		$positive = $match.Groups['n'].Value -ne 'n' -and $match.Groups['x'].Value -ne '!'
		$result = $IsPreprocTrue -eq $positive
		if ($result) {
			return $match.Groups['ifsect'].Value + $extra
		}
		if ($match.Groups['elsesect'].Success) {
			return $match.Groups['elsesect'].Value + $extra
		}
		return "`n"
	}
	$script:NewFileContents = [regex]::Replace($script:NewFileContents, $matcher, $evaluator)
}

function Assert-OutputNotNewer([string] $InputPath, [string] $OutputPath) {
	if ([IO.File]::Exists($OutputPath) -and
		[IO.File]::GetLastWriteTimeUtc($OutputPath) -gt [IO.File]::GetLastWriteTimeUtc($InputPath)) {
		throw "Aborting generic to specific script, output file `"$([IO.Path]::GetFileName($OutputPath))`" modified later than input `"$([IO.Path]::GetFileName($InputPath))`"."
	}
}

function Write-ReadOnlyFile([string] $Path, [string] $Contents) {
	if ([IO.File]::Exists($Path)) {
		[IO.File]::SetAttributes($Path, [IO.FileAttributes]::Normal)
		[IO.File]::Delete($Path)
	}
	$utf8WithoutBom = New-Object Text.UTF8Encoding($false)
	[IO.File]::WriteAllText($Path, $Contents, $utf8WithoutBom)
	[IO.File]::SetAttributes($Path, [IO.FileAttributes]::ReadOnly)
}

function New-ConsoleVariant(
	[string] $InputPath,
	[string] $OutputPath,
	[string] $TargetPlatform,
	[bool] $Utf8,
	[bool] $Wide
) {
	Assert-OutputNotNewer $InputPath $OutputPath
	if ($Utf8 -and $Wide) {
		throw 'Both UTF-8 and Wide specified; only one must be.'
	}

	$fileContents = [IO.File]::ReadAllText($InputPath)
	if (!$Utf8 -and !$Wide) {
		Write-ReadOnlyFile $OutputPath $fileContents
		return
	}

	$isWindows = $TargetPlatform -eq 'Windows'
	$prefix = if ($Utf8) { 'u8' } else { 'L' }
	$numMatches = 0
	$literalFinder = '(?<strmname>(?:std::w?cout)|(?:lastTimeAndStatsSS))(?:(?<spcstrmop>\s*<<\s*)(?<strmdata>[^;<]+))+;'
	$matches = [regex]::Matches($fileContents, $literalFinder)
	if ($matches.Count -eq 0) {
		throw 'No string literal matches found.'
	}

	$evaluator = [Text.RegularExpressions.MatchEvaluator] {
		param($match)
		$result = $match.Groups['strmname'].Value
		$operators = $match.Groups['spcstrmop'].Captures
		$data = $match.Groups['strmdata'].Captures
		for ($index = 0; $index -lt $operators.Count; ++$index) {
			$result += $operators[$index].Value
			$value = $data[$index].Value
			if ($value[0] -eq '"' -or $value[0] -eq "'") {
				$result += $prefix
			}
			if ($value[0] -eq '(' -and $value.Contains('?')) {
				if ($value.Contains('\"')) {
					throw 'backslash quote in ternary'
				}
				$parts = $value.Split('"')
				$value = ''
				for ($partIndex = 0; $partIndex -lt $parts.Length; ++$partIndex) {
					if (($partIndex % 2) -eq 1) {
						$value += $prefix
					}
					if ($partIndex -gt 0) {
						$value += '"'
					}
					$value += $parts[$partIndex]
				}
			}
			$result += $value
			++$numMatches
		}
		return $result + ';'
	}

	$script:NewFileContents = [regex]::Replace($fileContents, $literalFinder, $evaluator)
	if ($Wide) {
		$script:NewFileContents = $script:NewFileContents.Replace('std::cout', 'std::wcout').Replace('std::cin', 'std::wcin')
	}
	$script:NewFileContents = $script:NewFileContents.Replace('GetPortFromInput("', "GetPortFromInput(${prefix}`"")

	if ($Wide) {
		$script:NewFileContents = $script:NewFileContents.Replace('!strcasecmp(argv[i], "', "!_wcsicmp(argv[i], ${prefix}`"")
		$script:NewFileContents = $script:NewFileContents.Replace('int main(', 'int wmain(')
		$script:NewFileContents = $script:NewFileContents.Replace('std::strtoul(', 'std::wcstoul(')
		$script:NewFileContents = $script:NewFileContents.Replace('std::to_string(', 'std::to_wstring(')
		$script:NewFileContents = $script:NewFileContents.Replace('sprintf(', '_stprintf_s(')
	} elseif ($Utf8 -and $isWindows) {
		$script:NewFileContents = $script:NewFileContents.Replace('!strcasecmp(argv[i], "', "!_stricmp(argv[i], ${prefix}`"")
	}

	Replace-Preproc '_WIN32' $isWindows
	Replace-Preproc 'lw_utf8_console' $Utf8

	$script:NewFileContents = [regex]::Replace($script:NewFileContents, 'TXT\((.*?)\)', {
		param($match) $prefix + $match.Groups[1].Value
	})
	$script:NewFileContents = [regex]::Replace($script:NewFileContents, 'u8_lw\((.*?)\)', {
		param($match) if ($Wide) { "UTF8ToWide($($match.Groups[1].Value))" } else { $match.Groups[1].Value }
	})
	$script:NewFileContents = [regex]::Replace($script:NewFileContents, 'lw_u8\((.*?)\)', {
		param($match) if ($Wide) { "WideToUTF8($($match.Groups[1].Value))" } else { $match.Groups[1].Value }
	})

	Write-ReadOnlyFile $OutputPath $script:NewFileContents
	Write-DebugInfo "Wrote to `"$OutputPath`" successfully ($numMatches stream values)."
}

try {
	$scriptPath = [IO.Path]::GetFullPath($PSCommandPath)
	$repoDir = [IO.Directory]::GetParent([IO.Path]::GetDirectoryName($scriptPath)).FullName
	$resolvedInputPath = if ([string]::IsNullOrWhiteSpace($InputPath)) {
		[IO.Path]::Combine($repoDir, 'GenericConsole.cpp')
	} else {
		[IO.Path]::GetFullPath($InputPath)
	}
	$outputDir = if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
		$repoDir
	} else {
		[IO.Path]::GetFullPath($OutputDirectory)
	}
	[IO.Directory]::CreateDirectory($outputDir) | Out-Null

	New-ConsoleVariant $resolvedInputPath ([IO.Path]::Combine($outputDir, 'WindowsUTF8Console.cpp')) 'Windows' $true $false
	New-ConsoleVariant $resolvedInputPath ([IO.Path]::Combine($outputDir, 'LinuxConsole.cpp')) 'Linux' $true $false
	New-ConsoleVariant $resolvedInputPath ([IO.Path]::Combine($outputDir, 'WindowsWideConsole.cpp')) 'Windows' $false $true
} catch {
	Write-Error $_
	exit 1
}

