# 🕵️ PDF-Timestamping-with-TSA
1. **PDF Timestamping 기능:** PDF 파일에 Timestamp를 추가하는 주요 목적을 갖고 있습니다. Timestamp는 특정 시간에 문서가 존재했음을 보장하는 역할을 합니다.
2. Kotlin **및 PDFBox 사용:** Kotlin 프로그래밍 언어를 사용하여 개발되었으며, PDFBox 라이브러리를 이용하여 PDF 파일을 다룹니다. PDFBox는 Java로 작성된 오픈 소스 라이브러리로, PDF 파일을 읽고 쓰는 데 사용됩니다.
3. **TSAClient 호출:** TSA로부터 Timestamping 서비스를 호출하기 위해 TSAClient를 사용합니다. TSA는 Time-Stamp Authority의 약자로, 특정 시간에 문서가 서명되었음을 확인하는 서비스를 제공합니다.

‘PDF Timestamping with TSA’ 프로젝트는 전자 문서의 무결성을 확보하고 문서가 특정 시점에 존재했음을 입증하는 데 사용될 수 있는 보안 기술인 Timestamping을 구현했습니다. 

Kotlin 언어를 사용했으며 PDF파일과 인증서(cert)를 input으로 넣으면 output으로 Timestamp(타임스탬프)가 적용된 인증 PDF가 나옵니다. 

이 프로젝트에서는 Apache PDFBox 라이브러리를 활용하여 TSA(Time-Stamp Authority)로부터 TSAClient를 호출합니다.
<br/>
<br/>

# 👉 프로젝트에 필요한 Input 파일

- 이 프로젝트에는 input으로 pdf, pfx 파일이 필요합니다.
    - sample로 pdf, pfx, 인증이 완료된 pdf 이렇게 총 3개 파일을 넣어놨습니다.
- pfx 파일을 직접 만드는 법은 다음과 같습니다.
    1. openssl을 설치
    2. openssl을 이용해 → key 파일을 만들고
    3. key 파일을 이용해 → csr 파일을 만들고
    4. csr, cnf, key 파일을 이용해 → crt 파일을 만들고
    5. crt, key 파일을 이용해 → pfx 파일 생성!

<br/>

- 생성한 인증서 <br/>
![Screenshot_40](https://github.com/Sean-creative/PDF-Timestamping-with-TSA/assets/49125201/ddbe9fd1-3eba-4863-8ecb-f4b620b91874)

- 서비스 실행을 완료했을 때
![Screenshot_41](https://github.com/Sean-creative/PDF-Timestamping-with-TSA/assets/49125201/717c1e7c-1527-48b9-8b0f-5e550736dadd)

<br/>

### 해당 프로젝트를 참조했습니다.
-  https://github.com/ETDA/PDFTimestamping


