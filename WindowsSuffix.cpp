// This is Windows Suffix cpp
void UntieConsoleInput()
{
	std::cout.tie(nullptr);
	std::wcout.tie(nullptr);
}
void RetieConsoleInput()
{
	std::cout.tie(&std::cin);
	std::wcout.tie(&std::wcin);
}

// End of Windows Suffix cpp
