make -j 64 && 
make modules -j 64 && 
sudo make modules_install -j 64 && 
sudo make install && 
sudo update-grub &&
sudo reboot
