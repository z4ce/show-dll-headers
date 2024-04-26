package main

import (
	"debug/pe"
	"fmt"
	"log"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Usage: %s <dll_path>", os.Args[0])
	}

	dllPath := os.Args[1]
	dll, err := pe.Open(dllPath)
	if err != nil {
		log.Fatalf("Error opening DLL file: %s", err)
	}
	defer dll.Close()

	displayPEHeaders(dll)
}

// displayPEHeaders prints the headers from the PE file
func displayPEHeaders(dll *pe.File) {
	fmt.Println("File Header:")
	fmt.Printf("  Machine: %v\n", dll.FileHeader.Machine)
	fmt.Printf("  Number of Sections: %d\n", dll.FileHeader.NumberOfSections)
	fmt.Printf("  TimeDateStamp: %d\n", dll.FileHeader.TimeDateStamp)
	fmt.Printf("  Pointer to Symbol Table: %d\n", dll.FileHeader.PointerToSymbolTable)
	fmt.Printf("  Number of Symbols: %d\n", dll.FileHeader.NumberOfSymbols)
	fmt.Printf("  Size of Optional Header: %d\n", dll.FileHeader.SizeOfOptionalHeader)
	fmt.Printf("  Characteristics: %d\n", dll.FileHeader.Characteristics)
	fmt.Printf("Imported Libraries: \n")
	elements, err := dll.ImportedLibraries()
	if err != nil {
		fmt.Printf("Failed to load imported libraries\n")
	} else {
		for _, element := range elements {
			fmt.Printf("   %v\n", element)
		}
	}

	fmt.Printf("Symbols: ")
	for _, element := range dll.Symbols {
		fmt.Printf("   %v\n", element.Name)

	}

	if dll.OptionalHeader != nil {
		fmt.Println("Optional Header:")
		switch oh := dll.OptionalHeader.(type) {
		case *pe.OptionalHeader32:
			fmt.Printf("  Base of Data: %x\n", oh.BaseOfData)
			fmt.Printf("  Image Base: %x\n", oh.ImageBase)
			fmt.Printf("  Section Alignment: %x\n", oh.SectionAlignment)
			fmt.Printf("  File Alignment: %x\n", oh.FileAlignment)
			fmt.Printf("  OS Version: %d.%d\n", oh.MajorOperatingSystemVersion, oh.MinorOperatingSystemVersion)
			fmt.Printf("  Image Size: %x\n", oh.SizeOfImage)
			fmt.Printf("  Headers Size: %x\n", oh.SizeOfHeaders)
		case *pe.OptionalHeader64:
			fmt.Printf("  Image Base: %x\n", oh.ImageBase)
			fmt.Printf("  Section Alignment: %x\n", oh.SectionAlignment)
			fmt.Printf("  File Alignment: %x\n", oh.FileAlignment)
			fmt.Printf("  OS Version: %d.%d\n", oh.MajorOperatingSystemVersion, oh.MinorOperatingSystemVersion)
			fmt.Printf("  Image Size: %x\n", oh.SizeOfImage)
			fmt.Printf("  Headers Size: %x\n", oh.SizeOfHeaders)
		}
	}
}
