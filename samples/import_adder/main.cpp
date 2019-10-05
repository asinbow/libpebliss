#include <iostream>
#include <fstream>
#include <pe_bliss.h>
#ifdef PE_BLISS_WINDOWS
#include "lib.h"
#endif

using namespace pe_bliss;

// An example showing how to add a new import to the import table of a PE file
int main(int argc, char *argv[])
{
	if (argc != 2)
	{
		std::cout << "Usage: import_adder.exe PE_FILE" << std::endl;
		return 0;
	}

	// Open the file
	std::ifstream pe_file(argv[1], std::ios::in | std::ios::binary);
	if (!pe_file)
	{
		std::cout << "Cannot open " << argv[1] << std::endl;
		return -1;
	}

	try
	{
		// Create an instance of a PE or PE + class using a factory
		pe_base image(pe_factory::create_pe(pe_file));

		// Get the list of imported libraries and functions.
		imported_functions_list imports(get_imported_functions(image));

		// Create a new library from which we will import functions.
		import_library new_lib;
		new_lib.set_name("kaimi_dx.dll"); // Let it be kaimi_dx.dll

		// Add a couple of import functions to it.
		imported_function func;
		func.set_name("Tralala"); // One import - named Tralala
		func.set_iat_va(0x1);	 // Write a non-zero absolute address in the import address table

		imported_function func2;
		func2.set_ordinal(5);  // Other import - by ordinal 5
		func2.set_iat_va(0x2); // Write a non-zero absolute address in the import address table

		// We have specified incorrect contents (0x1 and 0x2) for the cells where the addresses of the imported functions will be written
		// It doesn't matter in the general case, because these values ​​are always overwritten by the loader.
		// These addresses are important only if the exe file has import bound

		// Add Imports
		new_lib.add_import(func);
		new_lib.add_import(func2);
		imports.push_back(new_lib); // Add imported library to imports

		// You can edit existing imports

		// But we'll just rebuild the import table
		// It will be larger than before our editing
		// so we write it in a new section so that everything fits
		// (we cannot expand existing sections, unless the section is right at the end of the file)
		section new_imports;
		new_imports.get_raw_data().resize(1);						// We cannot add empty sections, so let it be the initial data size 1
		new_imports.set_name("new_imp");							// Section Name
		new_imports.readable(true).writeable(true);					// Available for read and write
		section &attached_section = image.add_section(new_imports); // Add a section and get a link to the added section with calculated dimensions

		// Structure responsible for import reassembler settings
		import_rebuilder_settings settings(true, false);			 // Modify the PE header and do not clear the IMAGE_DIRECTORY_ENTRY_IAT field
		rebuild_imports(image, imports, attached_section, settings); // Rebuild Imports

		// Create a new PE file
		std::string base_file_name(argv[1]);
		std::string::size_type slash_pos;
		if ((slash_pos = base_file_name.find_last_of("/\\")) != std::string::npos)
			base_file_name = base_file_name.substr(slash_pos + 1);

		base_file_name = "new_" + base_file_name;
		std::ofstream new_pe_file(base_file_name.c_str(), std::ios::out | std::ios::binary | std::ios::trunc);
		if (!new_pe_file)
		{
			std::cout << "Cannot create " << base_file_name << std::endl;
			return -1;
		}

		// Rebuild PE file
		rebuild_pe(image, new_pe_file);

		std::cout << "PE was rebuilt and saved to " << base_file_name << std::endl;
	}
	catch (const pe_exception &e)
	{
		// If an error occurred
		std::cout << "Error: " << e.what() << std::endl;
		return -1;
	}

	return 0;
}
