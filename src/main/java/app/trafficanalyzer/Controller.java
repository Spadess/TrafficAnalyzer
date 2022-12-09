package app.trafficanalyzer;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.collections.transformation.FilteredList;
import javafx.collections.transformation.SortedList;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.layout.VBox;
import javafx.scene.paint.Color;
import javafx.stage.*;
import java.io.File;
import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.ResourceBundle;
import logic.*;
import logic.Headers.*;
public class Controller implements Initializable {
    @FXML
    private Label SelectLayer, FilterLabel, Status, LayerSize, Results;
    @FXML
    private TextField Filter;
    @FXML
    private TextArea LayerDetails, RawHexDetails;
    @FXML
    private MenuItem Export, ExportFG, Clear, FlowGraphMode, RegularMode;
    @FXML
    private Button Ethernetbtn, IPv4btn, TCPbtn, HTTPbtn;
    @FXML
    private TableColumn<Frame, Integer> FrameNumber, FlowNumber;
    @FXML
    private TableColumn<Frame, String> DestIP, DestPort, Protocol, SourceIP,SourcePort, Size;
    @FXML
    private TableView<Frame> FrameTable;
    ObservableList<Frame> OLFrames = FXCollections.observableArrayList();
    ObservableList<Frame> OLSF = FXCollections.observableArrayList(); //for export method
    ObservableList<Frame> OLFlow = FXCollections.observableArrayList(); //for showflowgraphmode

    ArrayList<String> FrameStringList;
    String SelectedFrameString;
    Ethernet ethernet = null; IPv4 ipv4 = null; TCP tcp = null; HTTP http = null;
    Frame currentFrame = null, f = null;
    int ethhlen = 14; int ipv4hlen = 0; int tcphlen = 0, HighlightOffset = 0;
    double protocol_width;

    @FXML
    protected void OpenFileImport() {
        FileChooser filechooser = new FileChooser();
        filechooser.setTitle("Select the text file to import");
        filechooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("Text Files", "*.txt"));
        File file = filechooser.showOpenDialog(null);

        try {
            FrameStringList = Reader.FrameFilter(file.getAbsolutePath());
        } catch (Exception e) {
            if (file == null) return;
            Status.setText(e.getMessage());
            Status.setTextFill(Color.RED);
            Status.setVisible(true);
            SelectedFrameString = null;
            LayerDetails.clear();
            RawHexDetails.clear();
            Ethernetbtn.setDisable(true);
            FlowGraphMode.setDisable(true);
            RegularMode.setDisable(true);
            IPv4btn.setDisable(true);
            TCPbtn.setDisable(true);
            HTTPbtn.setDisable(true);
            Ethernetbtn.setVisible(false);
            IPv4btn.setVisible(false);
            TCPbtn.setVisible(false);
            HTTPbtn.setVisible(false);
            SelectLayer.setDisable(true);
            Filter.setDisable(true);
            FilterLabel.setDisable(true);
            Export.setDisable(true);
            ExportFG.setDisable(true);
            if(!OLFrames.isEmpty() || !OLFlow.isEmpty()) Clear.setDisable(false);
            else Clear.setDisable(true);
            Protocol.setText("Protocol");
            Protocol.setPrefWidth(protocol_width);
            Protocol.setStyle("-fx-alignment: CENTER;");
            SourceIP.setSortable(true); DestIP.setSortable(true);
            SourcePort.setSortable(true); DestPort.setSortable(true); Protocol.setSortable(true);
            FlowNumber.setVisible(false); FrameNumber.setVisible(true); Size.setVisible(true);
            return;
        }
        Filter.clear();
        Filter.setDisable(true);
        LayerSize.setText("");
        Results.setText("");
        Protocol.setText("Protocol");
        Protocol.setPrefWidth(protocol_width);
        Protocol.setStyle("-fx-alignment: CENTER;");
        if (!OLFrames.isEmpty()) ClearWindow();
        for (String str : FrameStringList) {
            ethernet = null;
            ipv4 = null;
            tcp = null;
            http = null;
            SelectedFrameString = str;
            int ByteCount = Reader.CountBytes(SelectedFrameString);
            if (SelectedFrameString != null) {
                try{ //pour la taille minimale
                    ethernet = new Ethernet(Reader.TrimBytes(SelectedFrameString, 0, ByteCount));
                    try { //pour verifier le protocole/version
                        ethernet.checkType();
                    } catch (Exception e) {
                        f = new Frame(SelectedFrameString, ethernet, null, null, null);
                        OLFrames.add(f);
                        f.setError(e.getMessage());
                        continue;
                    }
                } catch(Exception e) {
                    f = new Frame(SelectedFrameString, null, null, null, null);
                    OLFrames.add(f);
                    f.setError(e.getMessage());
                    continue;
                }
                if (ethernet != null) {
                    try{
                        ipv4 = new IPv4(Reader.TrimBytes(SelectedFrameString, ethhlen, ByteCount - ethhlen));
                        try {
                            ipv4.checkProtocol();
                            //if(ipv4.getVersion() != 4){
                            //f = new Frame(SelectedFrameString,ethernet,null,null,null); OLFrames.add(f);
                            //f.setError("IP Version not recognized");
                            //continue;
                            //}
                        } catch (Exception e) {
                            f = new Frame(SelectedFrameString, ethernet, ipv4, null, null);
                            OLFrames.add(f);
                            f.setError(e.getMessage());
                            continue;
                        }
                    } catch(Exception e) {
                        f = new Frame(SelectedFrameString, ethernet, null, null, null);
                        OLFrames.add(f);
                        f.setError(e.getMessage());
                        continue;
                    }
                    if (ipv4 != null) {
                        ipv4hlen = ipv4.getHeaderLength();
                        int TCPStart = ethhlen + ipv4hlen;
                        try {
                            tcp = new TCP(Reader.TrimBytes(SelectedFrameString, TCPStart, ByteCount - (ethhlen + ipv4hlen)));
                            try {
                                tcp.checkPorts();
                            } catch (Exception e) {
                                f = new Frame(SelectedFrameString, ethernet, ipv4, tcp, null);
                                OLFrames.add(f);
                                f.setError(e.getMessage());
                                continue;
                            }
                        } catch(Exception e) {
                            f = new Frame(SelectedFrameString, ethernet, ipv4, null, null);
                            OLFrames.add(f);
                            f.setError(e.getMessage());
                            continue;
                        }
                        if (tcp != null) {
                            tcphlen = tcp.getHeaderLength();
                            int HTTPStart = ethhlen + ipv4hlen + tcphlen;
                            try {
                                http = new HTTP(Reader.TrimBytes(SelectedFrameString, HTTPStart, ByteCount - (ethhlen + ipv4hlen + tcphlen)));
                            } catch (Exception e) {
                                http = null;
                            }
                        }
                    }
                    OLFrames.add(new Frame(SelectedFrameString, ethernet, ipv4, tcp, http));
                }
            }
        }
            Export.setDisable(true);
            ExportFG.setDisable(true);
            FlowGraphMode.setDisable(true);
            RegularMode.setDisable(true);
            SourceIP.setSortable(true); DestIP.setSortable(true);
            SourcePort.setSortable(true); DestPort.setSortable(true); Protocol.setSortable(true);
            FlowNumber.setVisible(false); FrameNumber.setVisible(true); Size.setVisible(true);
            FrameTable.getSelectionModel().setSelectionMode(SelectionMode.MULTIPLE);
            if (!OLFrames.isEmpty()) {
                FrameTable.setItems(OLFrames);
                Results.setText(OLFrames.size()+" Frame(s)");
                Status.setText("File imported successfully");
                Status.setTextFill(Color.GREEN);
                Clear.setDisable(false);
                FilterLabel.setDisable(false);
                Filter.setDisable(false);
                Ethernetbtn.setVisible(false);
                IPv4btn.setVisible(false);
                TCPbtn.setVisible(false);
                HTTPbtn.setVisible(false);
                FlowGraphMode.setDisable(false);
                RegularMode.setDisable(false);
            }
        }
        @FXML
        protected void showLayerDetails () {
            currentFrame = FrameTable.getSelectionModel().getSelectedItem();
            if (!OLFrames.isEmpty() && currentFrame != null) {
                Status.setText("");
                if (!currentFrame.getError().equals("")) {
                    Status.setText(currentFrame.getError());
                    Status.setTextFill(Color.RED);
                }
                LayerSize.setText("Frame " + currentFrame.getFrameNo() + ", " + currentFrame.getSize() + " bytes");
                Export.setDisable(false);
                ExportFG.setDisable(false);
                LayerDetails.clear();
                Ethernetbtn.setDisable(true);
                IPv4btn.setDisable(true);
                TCPbtn.setDisable(true);
                HTTPbtn.setDisable(true);
                Ethernetbtn.setVisible(false);
                IPv4btn.setVisible(false);
                TCPbtn.setVisible(false);
                HTTPbtn.setVisible(false);
                RawHexDetails.setText(currentFrame.getRawhex());
                if (currentFrame.getEthernet() != null) {
                    SelectLayer.setDisable(false);
                    Ethernetbtn.setDisable(false);
                    Ethernetbtn.setVisible(true);
                    if (currentFrame.getIpv4() != null) {
                        IPv4btn.setDisable(false);
                        IPv4btn.setVisible(true);
                        if (currentFrame.getTcp() != null) {
                            TCPbtn.setDisable(false);
                            TCPbtn.setVisible(true);
                            if (currentFrame.getHttp() != null) {
                                HTTPbtn.setDisable(false);
                                HTTPbtn.setVisible(true);
                            }
                        }
                    }
                }
            }
        }

        @FXML
        protected void showEthernet () {
            LayerDetails.setText(currentFrame.getEthernet().toString());
            RawHexDetails.selectRange(0, (ethhlen - 1) * 3 + 2);
            RawHexDetails.setStyle("-fx-highlight-fill: lightblue;");
            LayerSize.setText("Frame " + currentFrame.getFrameNo() + " | Ethernet (eth), 14 bytes");
        }
        @FXML
        protected void showIPv4 () {
            LayerDetails.setText(currentFrame.getIpv4().toString());
            HighlightOffset = (ethhlen - 1) * 3 + 2 + 1;
            ipv4hlen = currentFrame.getIpv4hlen();
            RawHexDetails.selectRange(HighlightOffset, HighlightOffset + ((ipv4hlen - 1) * 3) + 2);
            RawHexDetails.setStyle("-fx-highlight-fill: lightblue;");
            LayerSize.setText("Frame " + currentFrame.getFrameNo() + " | Internet Protocol Version 4 (ip), " + currentFrame.getIpv4().getHeaderLength() + " bytes");
        }
        @FXML
        protected void showTCP () {
            LayerDetails.setText(currentFrame.getTcp().toString());
            ipv4hlen = currentFrame.getIpv4hlen();
            HighlightOffset = (ethhlen - 1) * 3 + 2 + 1 + (ipv4hlen - 1) * 3 + 2 + 1;
            tcphlen = currentFrame.getTcphlen();
            RawHexDetails.selectRange(HighlightOffset, HighlightOffset + ((tcphlen - 1) * 3) + 2);
            RawHexDetails.setStyle("-fx-highlight-fill: lightblue;");
            LayerSize.setText("Frame " + currentFrame.getFrameNo() + " | Transmission Control Protocol (tcp), " + currentFrame.getTcp().getHeaderLength() + " bytes");
        }

        @FXML
        protected void showHTTP () {
            LayerDetails.setText(currentFrame.getHttp().toString());
            ipv4hlen = currentFrame.getIpv4hlen();
            tcphlen = currentFrame.getTcphlen();
            HighlightOffset = (ethhlen - 1) * 3 + 2 + 1 + (ipv4hlen - 1) * 3 + 2 + 1 + (tcphlen - 1) * 3 + 2 + 1;
            int httplen = currentFrame.getHttp().getHttpLen();
            RawHexDetails.selectRange(HighlightOffset, HighlightOffset + ((httplen - 1) * 3) + 2);
            RawHexDetails.setStyle("-fx-highlight-fill: lightblue;");
            LayerSize.setText("Frame " + currentFrame.getFrameNo() + " | Hypertext Transfer Protocol (http), " + httplen + " bytes");
        }


        @FXML
        protected void OpenFileExport () throws Exception {
            FileChooser filechooser = new FileChooser();
            FrameTable.getSelectionModel().setSelectionMode(SelectionMode.MULTIPLE);
            filechooser.setTitle("Save Packet analysis as Text File");
            filechooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("Text File", "*.txt"));
            File file = filechooser.showSaveDialog(null);
            if (file != null) {
                PrintWriter out = new PrintWriter(file);
                OLSF = FrameTable.getSelectionModel().getSelectedItems(); //make an observ list out of the selected frames from the table
                out.println("Network Traffic Analyzer Export - " + Reader.getTime() + "\n");
                for (Frame frame : OLSF) {
                    if (frame != null) {
                        out.println("\n\n\t\t.......................................................");
                        out.println("\t\t\t\tFrame No. " + frame.getFrameNo() + " ("+ frame.getSize() + " bytes)");
                        out.println("\t\t.......................................................");
                        if (frame.getEthernet() != null) {
                            out.println("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                            out.println("\tEthernet Layer");
                            out.println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
                            out.print(frame.getEthernet().toString());
                            if (frame.getIpv4() != null) {
                                out.println("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                                out.println("\tIPv4 Layer");
                                out.println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
                                out.print(frame.getIpv4().toString());
                                if (frame.getTcp() != null) {
                                    out.println("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                                    out.println("\tTCP Layer");
                                    out.println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
                                    out.print(frame.getTcp().toString());
                                    if (frame.getHttp() != null) {
                                        out.println("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                                        out.println("\tHTTP Layer");
                                        out.println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
                                        out.print(frame.getHttp().toString());
                                    }
                                }
                            }
                        }
                    }
                }
                out.close();
                Status.setText("File exported successfully");
                Status.setTextFill(Color.GREEN);
            }
        }

        @FXML
        public void OpenFileExportFG() throws Exception{
            FileChooser filechooser = new FileChooser();
            FrameTable.getSelectionModel().setSelectionMode(SelectionMode.MULTIPLE);
            filechooser.setTitle("Save Packet analysis as Text File");
            filechooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("Text File", "*.txt"));
            File file = filechooser.showSaveDialog(null);
            if (file != null) {
                PrintWriter out = new PrintWriter(file);
                OLSF = FrameTable.getSelectionModel().getSelectedItems(); //make an observ list out of the selected frames from the table
                out.println("Network Traffic Analyzer Export - " + Reader.getTime() + "\n");
                out.println("Format: Source IP | Source Port ------------> Destination Port | Destination IP\n\n\n");
                int i=0;
                for (Frame frame : OLSF) {
                    if(frame!=null && frame.getIpv4()!=null && frame.getTcp()!= null){
                        if(frame.getFlowNo() !=i){
                            out.println("\t\t...................................................");
                            out.println("\t\t\t\tFlow Number "+frame.getFlowNo());
                            out.println("\t\t...................................................\n");
                        }


                        out.println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
                        out.print(frame.getSrcip() +"\t" +frame.getSrcport() +"\t------------>\t" +frame.getDestport() +"\t"+ frame.getDestip() +"\n");
                        if(frame.getProtocol().contains("TCP")){
                            StringBuilder sb = new StringBuilder();
                            frame.getTcp().toString();
                            sb.append("TCP: ").append(frame.getTcp().getActiveFlags()).append(" Seq=").append(frame.getTcp().getSequenceNumber()).append(" Ack=").append(frame.getTcp().getAcknowledgementNumber());
                            if(frame.getTcp().getCalculatedWindow()!=-1) sb.append(" Win=").append(frame.getTcp().getCalculatedWindow());
                            else sb.append(" Win=").append(frame.getTcp().getWindow());
                            if(frame.getTcp().getMSS()!=-1){
                                sb.append("\nMSS=").append(frame.getTcp().getMSS());
                                if(frame.getTcp().getTSval()!=-1 && frame.getTcp().getTSecr()!=-1) sb.append(" TSval=").append(frame.getTcp().getTSval()).append(" TSecr=").append(frame.getTcp().getTSecr());
                                if(frame.getTcp().check_SACK()) sb.append(" SACK_PERM");
                            }
                            else{
                                if(frame.getTcp().getTSval()!=-1 && frame.getTcp().getTSecr()!=-1){
                                    sb.append("\nTSval=").append(frame.getTcp().getTSval()).append(" TSecr=").append(frame.getTcp().getTSecr());
                                    if(frame.getTcp().check_SACK()) sb.append(" SACK_PERM");
                                }
                                else {
                                    if(frame.getTcp().check_SACK()) sb.append("\nSACK_PERM");
                                }
                            }
                            out.println(sb.toString());
                        }
                        else if(frame.getProtocol().contains("HTTP")){
                            out.print("HTTP: " + frame.getHttp().getHttpMethod());
                        }
                        out.println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n");
                        i = frame.getFlowNo();
                    }
                }
                out.close();
                Status.setText("File exported successfully");
                Status.setTextFill(Color.GREEN);
            }
        }

        @FXML
        protected void showAbout () {
            final Stage dialog = new Stage();
            dialog.setResizable(false);
            dialog.initModality(Modality.NONE);
            VBox dialogVbox = new VBox();
            TextArea about = new TextArea();
            about.setText("Projet réalisé par Filip Kechek et Nourchen Riahi.\n" +
                    "Nous voudrions remercier M. le Professeur Prométhée Spathis et l'équipe pédagogique de l'UE LU3IN033 pour leur encadrement.");
            about.setStyle("-fx-font-size: 25");
            about.setWrapText(true);
            about.setEditable(false);
            about.setPrefWidth(800);
            about.setPrefHeight(200);
            dialogVbox.getChildren().add(about);
            Scene dialogScene = new Scene(dialogVbox, 800, 200);
            dialog.setScene(dialogScene);
            dialog.setTitle("About");
            dialog.show();
        }

        @FXML
        protected void showGuide () {
            final Stage dialog = new Stage();
            dialog.setResizable(false);
            dialog.initModality(Modality.NONE);
            VBox dialogVbox = new VBox();
            TextArea guide = new TextArea();
            guide.setText("Voici le lien vers notre présentation vidéo sur YouTube:\n\n"+
                            "Voici le lien vers le code source du projet sur Github:");
            guide.setStyle("-fx-font-size: 25;");
            guide.setWrapText(true);
            guide.setEditable(false);
            guide.setPrefWidth(800);
            guide.setPrefHeight(200);
            dialogVbox.getChildren().add(guide);
            Scene dialogScene = new Scene(dialogVbox, 800, 200);
            dialog.setScene(dialogScene);
            dialog.setTitle("Guide");
            dialog.show();
        }

        @FXML
        protected void ClearWindow () {
            LayerDetails.clear();
            RawHexDetails.clear();
            LayerSize.setText("");
            SelectLayer.setDisable(true);
            Ethernetbtn.setDisable(true);
            IPv4btn.setDisable(true);
            TCPbtn.setDisable(true);
            HTTPbtn.setDisable(true);
            Ethernetbtn.setVisible(false);
            IPv4btn.setVisible(false);
            TCPbtn.setVisible(false);
            HTTPbtn.setVisible(false);
            Filter.clear();
            Filter.setDisable(true);
            Results.setText("");
            OLFrames.clear();
            OLFlow.clear();
            Frame.resetCpt();
            FilterLabel.setDisable(true);
            Export.setDisable(true);
            ExportFG.setDisable(true);
            FlowGraphMode.setDisable(true);
            RegularMode.setDisable(true);
            Clear.setDisable(true);
            Protocol.setText("Protocol");
            Protocol.setPrefWidth(protocol_width);
            Protocol.setStyle("-fx-alignment: CENTER;");
            SourceIP.setSortable(true); DestIP.setSortable(true);
            SourcePort.setSortable(true); DestPort.setSortable(true); Protocol.setSortable(true);
            FlowNumber.setVisible(false); FrameNumber.setVisible(true); Size.setVisible(true);
            Status.setText("Window cleared");
            Status.setTextFill(Color.GREEN);
        }

        @FXML
        protected void quit () {
            OLFrames.clear();
            Filter.clear();
            Platform.exit();
        }
        public int FlowCount(){
            int max =0;
            if(!FrameTable.getItems().isEmpty()){
                for(Frame frame: FrameTable.getItems()){
                    if (max < frame.getFlowNo()) max = frame.getFlowNo();
                }
            }
            return max;
        }

        public int ConnectionCount(){
            int count = 0;
            if(!FrameTable.getItems().isEmpty()){
                for(Frame frame: FrameTable.getItems()){
                    if (frame.getTcp().getActiveFlags().equals("[SYN,ACK]")) count++;
                }
            }
            return count;
        }
        @FXML
        public void setFilter (){
            // Wrap the ObservableList in a FilteredList (initially display all data).
            FilteredList<Frame> filteredFrames;
            if(Protocol.getText().contains("Flow Details")) filteredFrames = new FilteredList<>(OLFlow, p -> true);
            else filteredFrames = new FilteredList<>(OLFrames, p -> true);
            //Set the filter Predicate whenever the filter changes.
            Filter.textProperty().addListener((observable, oldValue, newValue) -> {
                filteredFrames.setPredicate(frame -> {
                    // If filter text is empty, display all frames
                    if (newValue == null || newValue.isEmpty()) {
                        return true;
                    }
                    // Compare first name and last name of every person with filter text.
                    String lowerCaseFilter = newValue.toLowerCase();
                    if (frame.getSrcip().contains(lowerCaseFilter)) return true;
                    else if (frame.getSrcport().contains(lowerCaseFilter)) return true;
                    else if (frame.getProtocol().toLowerCase().contains(lowerCaseFilter)) return true;
                    else if (frame.getDestip().contains(lowerCaseFilter)) return true;
                    else if (frame.getDestport().contains(lowerCaseFilter)) return true;
                    else if (String.valueOf(frame.getSize()).contains(lowerCaseFilter)) return true;
                    else return false; // Does not match.

                });
                // Wrap the FilteredList in a SortedList.
                SortedList<Frame> sortedFrames = new SortedList<>(filteredFrames);
                // Bind the SortedList comparator to the TableView comparator.
                // Otherwise, sorting the TableView would have no effect.
                sortedFrames.comparatorProperty().bind(FrameTable.comparatorProperty());
                // Add sorted (and filtered) data to the table.
                FrameTable.setItems(sortedFrames);
                if(Protocol.getText().contains("Flow Details")){
                    Results.setText(sortedFrames.size()+ " Frame(s), "+FlowCount()+" Flow(s), "+ConnectionCount()+" Connection(s)");
                }
                else Results.setText(sortedFrames.size()+" Frame(s)");
                LayerDetails.clear();
                RawHexDetails.clear();
                SelectLayer.setDisable(true);
                Export.setDisable(true);
                ExportFG.setDisable(true);
            });
        }

        @FXML
        public void showFlowGraphMode(){
            if(OLFlow.isEmpty()) {
                //to regroup tcp segments from same connection
                int FlowNo = 0;
                for(int i=0;i< OLFrames.size();i++) {
                    if (OLFrames.get(i) != null && OLFrames.get(i).getTcp() != null) {
                        if (!OLFlow.contains(OLFrames.get(i))) {
                            FlowNo++;
                            OLFlow.add(OLFrames.get(i));
                            OLFrames.get(i).setFlowNo(FlowNo);
                        } else{continue;}
                        for (int j = i + 1; j < OLFrames.size(); j++) {
                            if ((OLFrames.get(i).getIpv4().getSourceIP().equals(OLFrames.get(j).getIpv4().getSourceIP())
                                    && OLFrames.get(i).getIpv4().getDestIP().equals(OLFrames.get(j).getIpv4().getDestIP()))
                                    || (OLFrames.get(i).getIpv4().getSourceIP().equals(OLFrames.get(j).getIpv4().getDestIP())
                                    && OLFrames.get(i).getIpv4().getDestIP().equals(OLFrames.get(j).getIpv4().getSourceIP()))) {
                                if (!OLFlow.contains(OLFrames.get(j))) {
                                    OLFlow.add(OLFrames.get(j));
                                    OLFrames.get(j).setFlowNo(FlowNo);
                                }
                            }
                        }
                    }
                }
            }
            for(Frame f: OLFlow){
                if(f.getHttp()!=null) {
                    f.setProtocol("HTTP: "+f.getHttp().getHttpMethod()+
                            "----------------------------------------------------------------------->"+"\n"+f.getTcp().getActiveFlags());
                }
                else {
                    StringBuilder sb = new StringBuilder();
                    f.getTcp().toString();
                    sb.append("TCP: ").append(f.getTcp().getActiveFlags()).append(" Seq=").append(f.getTcp().getSequenceNumber()).append(" Ack=").append(f.getTcp().getAcknowledgementNumber());
                    if(f.getTcp().getCalculatedWindow()!=-1) sb.append(" Win=").append(f.getTcp().getCalculatedWindow());
                    else sb.append(" Win=").append(f.getTcp().getWindow());
                    sb.append("\n----------------------------------------------------------------------->");
                    if(f.getTcp().getMSS()!=-1){
                        sb.append("\nMSS=").append(f.getTcp().getMSS());
                        if(f.getTcp().getTSval()!=-1 && f.getTcp().getTSecr()!=-1) sb.append(" TSval=").append(f.getTcp().getTSval()).append(" TSecr=").append(f.getTcp().getTSecr());
                        if(f.getTcp().check_SACK()) sb.append(" SACK_PERM");
                    }
                    else{
                        if(f.getTcp().getTSval()!=-1 && f.getTcp().getTSecr()!=-1){
                            sb.append("\nTSval=").append(f.getTcp().getTSval()).append(" TSecr=").append(f.getTcp().getTSecr());
                            if(f.getTcp().check_SACK()) sb.append(" SACK_PERM");
                        }
                        else {
                            if(f.getTcp().check_SACK()) sb.append("\nSACK_PERM");
                        }
                    }
                    f.setProtocol(sb.toString());
                }
            }
            FrameTable.getSortOrder().clear();
            FrameTable.setItems(OLFlow);
            SourceIP.setSortable(false); DestIP.setSortable(false); FlowNumber.setSortable(false);
            SourcePort.setSortable(false); DestPort.setSortable(false); Protocol.setSortable(false);
            FlowNumber.setCellValueFactory(new PropertyValueFactory<>("FlowNo"));
            FlowNumber.setStyle("-fx-alignment: CENTER;");
            Results.setText(OLFlow.size()+ " Frame(s), "+FlowCount()+" Flow(s), "+ConnectionCount()+" Connection(s)");

            FrameNumber.setVisible(false);
            FlowNumber.setVisible(true);
            Size.setVisible(false);
            Protocol.setPrefWidth(protocol_width + Size.getWidth());
            Protocol.setStyle("-fx-alignment: CENTER-LEFT;");
            Protocol.setText("Flow Details");

        }
        @FXML
        public void showRegularMode(){
            for (Frame f : OLFrames) {
                if (f != null) {
                    if(f.getEthernet()!=null){
                        f.setProtocol("Ethernet");
                        if(f.getIpv4()!=null){
                            f.setProtocol("IPv4");
                            if(f.getTcp()!=null){
                                f.setProtocol("TCP");//+f.getTcp().getActiveFlags());
                                if(f.getHttp()!=null){
                                    f.setProtocol("HTTP");//f.getHttp().getHttpMethod());
                                }
                            }
                        }
                    }
                }
            }
            FrameTable.setItems(OLFrames);
            SourceIP.setSortable(true); DestIP.setSortable(true);
            SourcePort.setSortable(true); DestPort.setSortable(true); Protocol.setSortable(true);
            Results.setText(OLFrames.size()+ " Frame(s)");
            FrameTable.getSortOrder().clear();
            FrameNumber.setSortType(TableColumn.SortType.ASCENDING);
            FrameTable.getSortOrder().add(FrameNumber);
            FrameTable.sort();
            FlowNumber.setVisible(false);
            FrameNumber.setVisible(true);
            Size.setVisible(true);
            Protocol.setPrefWidth(protocol_width);
            Protocol.setStyle("-fx-alignment: CENTER;");
            Protocol.setText("Protocol");
            ExportFG.setDisable(true);
        }

        @Override
        public void initialize (URL url, ResourceBundle resourceBundle){
            FrameNumber.setCellValueFactory(new PropertyValueFactory<>("FrameNo"));
            FrameNumber.setStyle("-fx-alignment: CENTER;");
            SourceIP.setCellValueFactory(new PropertyValueFactory<>("srcip"));
            SourceIP.setComparator(new IPComparator());
            SourceIP.setStyle("-fx-alignment: CENTER-LEFT;");
            SourcePort.setCellValueFactory(new PropertyValueFactory<>("srcport"));
            SourcePort.setComparator(new PortComparator());
            SourcePort.setStyle("-fx-alignment: CENTER;");
            DestIP.setCellValueFactory(new PropertyValueFactory<>("destip"));
            DestIP.setComparator(new IPComparator());
            DestIP.setStyle("-fx-alignment: CENTER-LEFT;");
            DestPort.setCellValueFactory(new PropertyValueFactory<>("destport"));
            DestPort.setComparator(new PortComparator());
            DestPort.setStyle("-fx-alignment: CENTER;");
            Size.setCellValueFactory(new PropertyValueFactory<>("size"));
            Size.setStyle("-fx-alignment: CENTER;");
            Protocol.setCellValueFactory(new PropertyValueFactory<>("protocol"));
            Protocol.setStyle("-fx-alignment: CENTER;");
            protocol_width = Protocol.getWidth();
        }
}