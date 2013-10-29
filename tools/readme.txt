1) protector.res - is a protector section. It is added to a program which we need to 'protect'
2)CProtector_empty.exe - is an empty section payloader, 
that is, it can add it's last section to target exe. CProtector_empty hasnt protector.res,
and should be payloaded with it by Builder
3)Builder_for_cprotector.exe - simple builder. Injects section from selected .res file to a selected
empty CProtector instance

To build:
Builder_for_cprotector -> select protector.res -> select CProtector_empty_res
To protect:
Run Cprotector instance

CAUTION:
no source for Builder!!! do not modify it