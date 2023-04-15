This script is meant to be used together with the following repo:

https://github.com/Spore-Community/PNG-Downloader

The script acts as a helper to organize the downloaded creatures (png files) so you dont need to manually copy them to `My Spore Creations` folder or drag and drop each of them in the spore window.


## Usage

python3 spore_png_organizer.py --source_directory "D:\downloaded_pngs" --target_directory" "D:\my_spore_stuff"
- this will create a folder called `spore_creations` in `D:\my_spore_stuff\` and in this folder will contain the folder structure from `C:\Users\<USER>\Documents\My Spore Creations\`
- use `--help` to see other useful options


## Notes

- In case the type of the png file cannot be detected (if it's a creature, building, adventure, etc.) then it will be saved in an `UNKNOWN` sub-folder
- If a png file contains incomplete data, then the file will be saved in in an `INCOMPLETE` sub-folder. Sometimes incomplete creatures can cause spore to crash, although it I had this problem with complete creatures too so the problem might be something else.
