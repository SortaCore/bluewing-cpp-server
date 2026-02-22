/* vim: set noet ts=4 sw=4 sts=4 ft=cs:
 *
 * Created by Darkwire Software.
 *
 * This file is for converting GenericConsole.cpp into Windows Wide and UTF-8 variants, and Linux (implicitly UTF-8).
 * It is triggered by Directory.Build.props, which Visual Studio auto-loads.
 *
 * It should never be necessary to build with ANSI plain literals, and most C++ compilers will convert u8 prefix text
 * into UTF-8 characters, even if the CRT itself does not support u8 literal strings.
 * 
 * It is not necessary to run this pre-build script unless you are editing all platforms, as the generated files
 * are uploaded as well.
 * https://learn.microsoft.com/en-us/visualstudio/msbuild/msbuild-roslyncodetaskfactory?view=visualstudio
 *
 * This file is available unlicensed; the MIT license of liblacewing/Lacewing Relay does not apply to this file.
*/
using System;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;

namespace BluewingCppServerTasks
{
	public class GenericToSpecificParser : Task
	{
		// Full path to input cpp file
		[Required] public string InputPath { get; set; }
		// Full path to output cpp file
		[Required] public string OutputPath { get; set; }
		// Expects Windows or Linux
		[Required] public string TargetPlat { get; set; }
		// If true, uses u8 string literal prefix
		[Required] public bool UTF8 { get; set; }
		// If true, uses L string literal prefix
		[Required] public bool Wide { get; set; }
		// If true, logs info, not just errors: default false
		public bool DebugOutput { get; set; }

		// Searches and matches contents of ifdef X, else // !X, endif // X
		// Ensures the ifs and endifs match, returns null if fine
		private string PreprocCountErrorCheck(string haystack, string needle)
		{
			const string preprocMatcher = @"(?m)#[ \t]*((?:if(?:n?def)?)|(?:else)|(?:endif))[ \t]*(?://)?[ \t]*!?_WIN32[ \t]*\n";
			Regex defCounter = new Regex(preprocMatcher.Replace("_WIN32", needle));
			MatchCollection mc = defCounter.Matches(haystack);
			// Would use .Count(x=>) but Linq refuses to load in MSBuild inline task
			uint numIfDefs = 0, numEndIfs = 0;
			foreach (Match m in mc)
			{
				if (m.Groups[1].Value.StartsWith("if"))
					++numIfDefs;
				else if (m.Groups[1].Value == "endif")
					++numEndIfs;
			}
			if (numIfDefs == 0)
				return $"Error: regex broken for detecting #ifdef {needle} (none found).";
			if (numIfDefs > numEndIfs)
				return $"Error: Too many #if(def) {needle} ({numIfDefs}) without enough #endif {needle} ({numEndIfs}).";
			if (numEndIfs > numIfDefs)
				return $"Error: Too many #endif {needle} ({numEndIfs}) without enough #if(def) {needle} ({numIfDefs}).";
			return null;
		}

		// Searches and matches contents of if X, ifdef X, else // X, endif // X
		// ifdef, else, endif must be commented as expected
		private bool ReplacePreproc(string from, bool isPreprocTrue)
		{
			string PreprocMatcher = @"(?m)^[ \t]*#[ \t]*?if(?<n>n?)(?:def)?[ \t]+(?<x>!?)_WIN32\s*\n(?<ifsect>(?:.|\n)*?)" +
				@"(?:\n[ \t]*?#[ \t]*?else[ \t]*\/\/[ \t]*!_WIN32[ \t]*\n(?<elsesect>(?:.|\n)+?))?\n" +
				@"[ \t]*?#[ \t]*?endif[ \t]*?\/\/[ \t]*?!?_WIN32[ \t]*\n(?<afterline>[ \t]*\n)?";
			Regex winDefClean = new Regex(PreprocMatcher.Replace("_WIN32", from));

			string countErr = PreprocCountErrorCheck(newFileContents, from);
			if (countErr != null)
			{
				LogError($"{countErr}\n");
				return false;
			}

			newFileContents = winDefClean.Replace(newFileContents, (Match m) => {
				LogInfo($"---- got match for {from}:\n{m.Value}\n----\n");
				// If after the #endif is a blank line, double the blanks
				string extra = "\n";
				if (m.Groups["afterline"].Success)
					extra = "\n\n";

				// preprocessor true is for #ifdef x
				// if it's #ifndef x or #if !x, reverse it
				bool result = isPreprocTrue == (m.Groups["n"].Value != "n" && m.Groups["x"].Value != "!");

				// returns contents of #if, if true
				if (result)
					return m.Groups["ifsect"].Value + extra;

				// returns contents of #else, if false, and we have an #else
				if (m.Groups["elsesect"].Success)
					return m.Groups["elsesect"].Value + extra;

				// No #else, just return blank
				return "\n";
			});
			return true;
		}

		// Logs as high importance message (writing to VS Output window)
		private Action<string> LogInfo;
		// Logs as error (aborting task and its build)
		private Action<string> LogError;
		// Generated new file contents
		private string newFileContents;

		// Called externally after all the public properties are set
		public override bool Execute()
		{
			// Set callbacks for logging
			if (DebugOutput)
				LogInfo = m => Log.LogMessage(MessageImportance.High, m);
			else
				LogInfo = m => { };
			LogError = m => Log.LogError(m);

			// Anyone modifying platform-specific CPP - someone not making a portable edit - won't be calling this task.
			// Anyone modifying the generic CPP file likely does not want to accidentally modify platform-specific cpp.
			if (File.Exists(OutputPath) && File.GetLastWriteTimeUtc(OutputPath) > File.GetLastWriteTimeUtc(InputPath))
			{
				LogError($"Aborting generic to specific script, output file \"{Path.GetFileName(OutputPath)}\" modified later than input \"{Path.GetFileName(InputPath)}\".");
				return false;
			}

			// We either appending u8 or L to string literals, not both
			if (UTF8 && Wide)
			{
				LogError("Both UTF-8 and Wide specified; only one must be.");
				return false;
			}

			// Erase output file, which might be marked read-only
			if (File.Exists(OutputPath))
			{
				File.SetAttributes(OutputPath, System.IO.FileAttributes.Normal);
				File.Delete(OutputPath);
			}
	
			// Nothing to do, copy as is
			if (!UTF8 && !Wide)
			{
				LogInfo("Nothing to do, copying as is.");
				File.Copy(InputPath, OutputPath, true);
				File.SetAttributes(OutputPath, FileAttributes.ReadOnly);
				return true;
			}

			bool IsWindows = TargetPlat == "Windows";
			string prefix = UTF8 ? "u8" : (Wide ? "L" : "");
			if (UTF8 || Wide)
			{
				int numMatches = 0;
				string fileContents = File.ReadAllText(InputPath);
				LogInfo($"Using string literal prefix: {prefix}");

				// Searching for text literals in a line after std::cout << or lastTimeAndStatsSS <<.
				// We then prepend the text prefix to the literals.
				Regex literalFinder = new Regex(@"(?<strmname>(?:std::w?cout)|(?:lastTimeAndStatsSS))(?:(?<spcstrmop>\s*<<\s*)(?<strmdata>[^;<]+))+;");
				MatchCollection mc = literalFinder.Matches(fileContents);
				if (mc.Count == 0)
				{
					LogError("No string literal matches found.");
					return false;
				}
			
				newFileContents = "";
				int pos = 0;
				foreach (Match m in mc)
				{
					newFileContents += fileContents.Substring(pos, m.Index - pos);
					pos = m.Index + m.Length;
				
					string str = m.Groups["strmname"].Value; 

					// Repeating group captures only work for MS's .NET regex engine; the other regex engines will store last capture alone.
				//	LogInfo($"Match [ {m} ] has { m.Groups["spcstrmop"].Captures.Count }, { m.Groups["strmdata"].Captures.Count } captures.");
					for (int i = 0; i < m.Groups["spcstrmop"].Captures.Count; ++i)
					{
						// add captured spacing + stream operator
						str += m.Groups["spcstrmop"].Captures[i].Value;
						// replace quoted text with prefixed text
						// non-literals gets ignored
						Capture c = m.Groups["strmdata"].Captures[i];
						string cap = c.Value;
						if (cap[0] == '"' || cap[0] == '\'')
							str += prefix;
						// If data is ternary with two+ string literals
						if (cap[0] == '(' && cap.Contains("?"))
						{
							// This code expects to split on double quote, and breaks if there's an escaped double quote
							if (cap.Contains("\\\""))
								LogError("backslash quote in ternary");

							// Produce list of x ? "a" : "b", splitting on "
							string[] spl = cap.Split('"');
							cap = "";
							for (int j = 0; j < spl.Length; ++j)
							{
								// Strings start at index 1, 3, etc. End at 2, 4. Add prefix to odd numbered.
								if ((j % 2) == 1)
									cap += prefix;
								// The first operator is boolean check, not text
								if (j > 0)
									cap += '"';
								cap += spl[j];
							}
						}
				
						str += cap;
						++numMatches;
					}
					str += ';';
				//	LogInfo("Conclusion str [ " + str + " ].");
					newFileContents += str;
				}
				newFileContents += fileContents.Substring(pos);
				// Wide uses wide streams
				if (Wide)
				{
					newFileContents = newFileContents.Replace("std::cout", "std::wcout")
						.Replace("std::cin", "std::wcin");
				}
				LogInfo($"Num literal matches: {numMatches}");

				// User input is also UTF-8 or Wide
				newFileContents = newFileContents.Replace("GetPortFromInput(\"", "GetPortFromInput(" + prefix + "\"");

				// The ol' switcheroo
				if (Wide)
				{
					newFileContents = newFileContents
						.Replace("!strcasecmp(argv[i], \"", "!_wcsicmp(argv[i], " + prefix + "\"")
						.Replace("int main(", "int wmain(")
						.Replace("std::strtoul(", "std::wcstoul(")
						.Replace("std::to_string(", "std::to_wstring(")
						.Replace("sprintf(", "_stprintf_s(");
				}

				// Windows uses stricmp instead of strcasecmp
				if (UTF8 && IsWindows)
				{
					newFileContents = newFileContents
						.Replace("!strcasecmp(argv[i], \"", "!_stricmp(argv[i], " + prefix + "\"");
				}

				// Replace the macros with there resulting prefix - this is basically what preprocessor does
				if (!ReplacePreproc("_WIN32", IsWindows) || !ReplacePreproc("lw_utf8_console", UTF8))
					return false;
		
				// Replace the macros with there resulting prefix - this is basically what preprocessor does
				newFileContents = new Regex(@"TXT\((.*?)\)").Replace(newFileContents, (Match m) => { return prefix + m.Groups[1].Value; });
				newFileContents = new Regex(@"u8_lw\((.*?)\)").Replace(newFileContents, (Match m) => {
					return Wide ? $"UTF8ToWide({m.Groups[1].Value})" : m.Groups[1].Value;
				});
				newFileContents = new Regex(@"lw_u8\((.*?)\)").Replace(newFileContents, (Match m) => {
					return Wide ? $"WideToUTF8({m.Groups[1].Value})" : m.Groups[1].Value;
				});

				File.WriteAllText(OutputPath, newFileContents);
				System.IO.File.SetAttributes(OutputPath, System.IO.FileAttributes.ReadOnly);
				LogInfo($"Wrote to \"{OutputPath}\" successfully.");
			}
			return true;
		}
	}
}
