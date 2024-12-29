int ReplaceComd(int k) {
	short int s0, s1, s2, i, b;
	char attrib = '\0', * FileName, * DirName;
	char gFileName[PATH_LEN];  // 存放文件全路径名
	char gDirName[PATH_LEN];   // 存放目录全路径名
	FCB* fcbp, * fcbp1;
	char buffer[SIZE + 1]; // 缓冲区，用于存储文件内容

	if (k < 1 || k > 2) {
		cout << "\n命令参数个数错误。\n";
		return -1;
	}

	// 获取文件名和目录名
	FileName = comd[1];
	if (k == 1) {  // 如果目录名参数缺省，则取代当前目录的同名文件
		strcpy_s(gDirName, sizeof(gDirName), curpath.cpath);
		DirName = FileName;
	}
	else {
		s0 = ProcessPath(comd[2], DirName, k, 0, '\020');  // 取DirName所在目录的首块号
		if (s0 < 1)  // 路径错误
			return s0;  // 失败，返回
		strcpy_s(gDirName, sizeof(gDirName), temppath);
	}
	strcpy_s(gFileName, sizeof(gFileName), gDirName);
	if (gFileName[strlen(gFileName) - 1] != '/') {
		strcat_s(gFileName, sizeof(gFileName), "/");
	}
	strcat_s(gFileName, sizeof(gFileName), FileName);  // 构造文件的全路径名

	// 检查文件是否存在
	s1 = FindFCB(FileName, s0, attrib, fcbp);  // 取FileName的首块号(查其存在性)
	if (s1 < 0) {
		cout << "\n要取代的文件不存在。\n";
		return -2;
	}

	// 检查被取代文件是否是只读、隐藏或系统文件
	if (fcbp->Fattrib & ((char)2 | (char)4)) {  // 隐藏或系统属性
		cout << "\n具有隐藏和系统属性的文件不能被取代。\n";
		return -3;
	}

	// 检查文件是否是只读属性
	if (fcbp->Fattrib & (char)1) {  // 只读属性
		char yn;
		cout << "\n被取代文件是只读属性，你确定要取代它吗？(y/n) ";
		cin >> yn;
		if (yn != 'Y' && yn != 'y')
			return 0;  // 不取代，返回
	}

	// 检查文件名指定的文件和被取代的文件是否是同一个文件
	if (strcmp(gFileName, temppath) == 0) {
		cout << "\n不能自己取代自己。\n";
		return -4;
	}

	// 读取源文件内容到缓冲区
	s2 = FindFCB(FileName, curpath.fblock, attrib, fcbp1);  // 查找文件名指定的文件
	if (s2 < 0) {
		cout << "\n文件名指定的文件不存在。\n";
		return -5;
	}
	int len = file_to_buffer(fcbp1, buffer); // 读取文件内容到缓冲区
	if (len < 0) {
		cout << "\n读取文件内容失败。\n";
		return -6;
	}

	// 删除目标文件的当前内容
	releaseblock(fcbp->Addr); // 释放目标文件占用的磁盘空间
	fcbp->Addr = 0; // 将目标文件的首块号设为0，表示空文件
	fcbp->Fsize = 0; // 将目标文件的大小设为0

	// 将缓冲区内容写入目标文件
	if (buffer_to_file(fcbp, buffer) != 1) { // 将缓冲区内容写入目标文件
		cout << "\n写入文件内容失败。\n";
		return -7;
	}

	cout << "\n文件" << FileName << "已成功取代" << gDirName << "中的同名文件。\n";
	return 1;
}